// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! /oauth2/authorize 端点 — 两段式票据授权码流程 + PKCE 强制 + consent 记忆。
//!
//! 处理 RFC 6749 §4.1 授权码流程，强制 PKCE（RFC 7636 S256 方法）。
//!
//! ## 流程（两段式票据）
//!
//! 1. 校验 response_type=code / PKCE（code_challenge + S256）/ client_id / redirect_uri
//! 2. 未登录 → 签发 32 字符随机票据，DAO `set_if_absent` 暂存完整请求（TTL 600s），
//!    重定向登录页（return_to 仅携带 resume 地址 + 票据，不回传请求参数，
//!    参数注入面被票据化结构性消除）
//! 3. 登录后凭票据 resume：原子消费票据（GETDEL，二次消费拒），恢复完整请求，
//!    对客户端存在性 / 白名单 / scope 做 fail-closed 重校验（往返期间注册可能变化）
//! 4. consent 记忆判定（scope 超集合并 + 属性快照哈希，见 `consent_decision`）：
//!    记忆覆盖 → 直接签发授权码；记忆不足 → 升级征询页（未配置则 interaction_required）
//! 5. 签发授权码（10 分钟 TTL，一次性使用）并重定向 redirect_uri?code=xxx&state=xxx

use crate::constants::DaoKeyPrefix;
use crate::context::tenant::current_tenant_id_strict;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;

/// 授权码有效期（10 分钟，RFC 6749 §4.1.2 建议 ≤ 10 分钟）。
const AUTH_CODE_TTL_SECONDS: u64 = 600;

/// authorize 暂存票据 TTL（10 分钟；登录往返的合理上限，对齐 tinyauth
/// CreateAuthorizeRequestTicket 的 10 分钟缓存窗口）。
const AUTHORIZE_TICKET_TTL_SECONDS: u64 = 600;

/// authorize 暂存票据长度（32 字符字母数字，对齐 tinyauth utils.GenerateString(32)）。
const AUTHORIZE_TICKET_LEN: usize = 32;

/// authorize 暂存票据 DAO key 前缀：`oauth2:authorize-ticket:{ticket}`。
const OAUTH2_AUTHORIZE_TICKET_KEY_PREFIX: &str = "oauth2:authorize-ticket:";

/// consent 记忆 DAO key 前缀：`oauth2:consent:{tenant_id}:{user_id}:{client_id}`。
const OAUTH2_CONSENT_KEY_PREFIX: &str = "oauth2:consent:";

/// OAuth2 refresh_token 的 DAO fallback key：`oauth2:rtoken:{token}`。
///
/// 未注入 `RefreshTokenRotation`（需 `db-sqlite`）的部署经 DAO 键值存储
/// 消费 refresh token（无 reuse detection，安全风险见 `token` 模块文档）。
fn oauth2_refresh_token_key(token: &str) -> String {
    debug_assert!(
        !token.contains(':'),
        "oauth2 refresh_token key: token must not contain ':' (ambiguous key)"
    );
    format!("oauth2:rtoken:{}", token)
}

/// authorize 暂存票据的 DAO key：`oauth2:authorize-ticket:{ticket}`。
fn authorize_ticket_key(ticket: &str) -> String {
    debug_assert!(
        !ticket.contains(':'),
        "authorize ticket key: ticket must not contain ':' (ambiguous key)"
    );
    format!("{}{}", OAUTH2_AUTHORIZE_TICKET_KEY_PREFIX, ticket)
}

/// consent 记忆的 DAO key：`oauth2:consent:{tenant_id}:{user_id}:{client_id}`。
///
/// tenant_id / user_id 为数值（不含 ':'），client_id 作为末段可安全承载含 ':'
/// 的标识（reconcile 解析用 `splitn(3, ':')` 保留末段完整性）。
fn consent_key(tenant_id: i64, user_id: i64, client_id: &str) -> String {
    debug_assert!(
        !client_id.contains(':'),
        "consent key: client_id must not contain ':' (ambiguous key)"
    );
    format!(
        "{}{}:{}:{}",
        OAUTH2_CONSENT_KEY_PREFIX, tenant_id, user_id, client_id
    )
}

/// 票据无效 / 过期 / 已消费的统一错误（不区分三者，避免向票据持有者泄露状态）。
fn ticket_invalid_error() -> GarrisonError {
    GarrisonError::OAuth2("oauth2-server-authorize-ticket-invalid-or-expired".into())
}

/// 「需要用户交互但 prompt=none 禁止交互」错误（OIDC Core §3.1.2.6）。
fn interaction_required_error() -> GarrisonError {
    GarrisonError::OAuth2("oauth2-server-authorize-interaction-required".into())
}

/// 授权码已签发 token 的吊销追踪记录 TTL（30 天，覆盖 refresh token 生命周期）。
///
/// 用于重放/双花检测时定位并吊销此前签发的 access/refresh token。
const CODE_USED_RECORD_TTL_SECONDS: u64 = 2_592_000;

/// 授权码已签发 token 的吊销追踪记录。
///
/// 授权码被原子消费（删除）后，其签发的 token 仍需可被定位吊销，
/// 因此将 `access_token` / `refresh_token` 单独持久化于此结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeUsedRecord {
    access_token: String,
    refresh_token: Option<String>,
}

/// code_verifier 最小长度（RFC 7636 §4.1）。
const CODE_VERIFIER_MIN_LEN: usize = 43;
/// code_verifier 最大长度（RFC 7636 §4.1）。
const CODE_VERIFIER_MAX_LEN: usize = 128;

/// S256 code_challenge 固定长度（BASE64URL_NO_PAD(SHA256(32B)) = 43 字符，RFC 7636 §4.2）。
///
/// 用于在 `verify_pkce` 入口校验 `code_challenge` 长度，防止外部传入超长字符串
/// 触发常量时间循环被放大成 CPU DoS（CWE-400）。
const S256_CHALLENGE_LEN: usize = 43;

/// URL 查询参数值编码集。
///
/// 编码控制字符 + 保留字符 + 不安全字符，防止参数注入和 URL 解析歧义。
/// `&` / `=` / `#` / `+` / `%` 等保留字符被编码，避免在查询参数值中被误解析。
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'%');

/// /oauth2/authorize 请求参数（query string）。
///
/// 两段式票据流程中，校验通过后的完整请求会序列化暂存（TTL 600s），
/// 登录后凭票据经 `AuthorizeHandler::resume` 原样恢复。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// 授权类型（必须为 "code"）。
    pub response_type: String,
    /// 客户端 ID。
    pub client_id: String,
    /// 重定向 URI（必须在客户端白名单中）。
    pub redirect_uri: String,
    /// 请求的 scope（空格分隔，可选）。
    pub scope: Option<String>,
    /// 客户端状态（原样回传，防 CSRF）。
    pub state: Option<String>,
    /// PKCE code_challenge（S256 方法：BASE64URL(SHA256(code_verifier))）。
    pub code_challenge: String,
    /// PKCE code_challenge_method（必须为 "S256"）。
    pub code_challenge_method: String,
}

/// /oauth2/authorize 响应。
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizeResponse {
    /// 成功：重定向到 redirect_uri?code=xxx&state=xxx。
    Redirect {
        /// 重定向目标 URL（含 code 和 state 参数）。
        location: String,
    },
    /// 需要用户交互：重定向到交互页面。
    ///
    /// 两种来源：未登录（`login_url` 指向登录页，return_to 仅携带 resume 地址 +
    /// 一次性票据）；consent 记忆不足（`login_url` 指向征询页并携带重入票据，
    /// 需 `with_consent_url` 配置，未配置时以 interaction_required 显性失败）。
    LoginRequired {
        /// 交互页面 URL（登录页或 consent 征询页，含 return_to/ticket 参数）。
        login_url: String,
    },
}

/// 授权码记录（存储在 DAO 中，10 分钟 TTL，一次性使用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// 授权码字符串（BASE64URL 编码的 32 字节随机数）。
    pub code: String,
    /// 关联的客户端 ID。
    pub client_id: String,
    /// 关联的 redirect_uri。
    pub redirect_uri: String,
    /// 授权的 scope 列表。
    pub scopes: Vec<String>,
    /// 授权用户 ID。
    pub user_id: i64,
    /// PKCE code_challenge（token 交换时验证 code_verifier）。
    pub code_challenge: String,
}

/// consent 征询判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentDecision {
    /// 记忆的 consent 完整覆盖本次请求（scope 子集 + 属性快照未变化）→ 免征询。
    Remembered,
    /// 需要重新征询。
    Required(ConsentRequiredReason),
}

/// 需要重新征询的具体原因（显性化，供征询页与审计区分处置）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentRequiredReason {
    /// 该 (tenant, user, client) 无 consent 记录（首次授权）。
    FirstGrant,
    /// 请求含未授 scope（超集合并语义：仅新增部分触发征询）。
    ScopeExpansion {
        /// 本次请求中尚未被授权的 scope。
        new_scopes: Vec<String>,
    },
    /// 属性快照哈希与当前属性不一致（属性名或属性值变化，粒度相关）。
    AttributesChanged,
    /// consent 记录不可解析 / 快照缺失——fail-safe 视为需要重新征询。
    SnapshotUnreadable,
}

/// 属性快照比较粒度（consent 重征询判定，对齐 cas ConsentReminderOptions 双粒度语义）。
///
/// 双粒度下名哈希恒参与比较；差异仅在值哈希是否参与：
/// - ATTRIBUTE_NAME：属性值变化不触发重征询（默认，cas 服务级 consent 的常见档位）
/// - ATTRIBUTE_VALUE：名 + 值哈希都比较，任一变化即重征询
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttributeSnapshotGranularity {
    /// 只比较属性名集合哈希（默认）。
    #[default]
    AttributeName,
    /// 属性名 + 属性值哈希都比较。
    AttributeValue,
}

/// 授权时服务可释放的单个属性视图（属性名 + 该名的候选值集合）。
pub type ConsentAttributes = (String, Vec<String>);

/// OIDC Core §3.1.2.1 prompt 参数语义子集（授权码流程相关项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizePrompt {
    /// 未指定 prompt：默认流程（未登录引导登录、consent 记忆判定）。
    #[default]
    None,
    /// prompt=none：不允许任何交互——未登录或 consent 不足一律
    /// `interaction_required` 显性失败，绝不弹登录/征询页。
    NoInteraction,
    /// prompt=login：即使已有会话也强制重走登录往返。
    ForceLogin,
    /// prompt=login 的别名形态（OIDC core §3.1.2.1 值集原文），语义同
    /// [`AuthorizePrompt::ForceLogin`]。
    Login,
}

/// consent 记忆记录（DAO 持久化，键 `oauth2:consent:{tenant}:{user}:{client}`，永久驻留）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsentRecord {
    /// 已授 scope 集合（超集合并语义：只增不减，字典序存储）。
    granted_scopes: Vec<String>,
    /// 授权时属性名集合的 SHA-512 十六进制摘要（双粒度都比较）。
    attribute_names_hash: String,
    /// 授权时属性值的 SHA-512 十六进制摘要（仅 ATTRIBUTE_VALUE 粒度参与比较；
    /// 恒双写，粒度配置切换不需要强制重征询）。
    attribute_values_hash: String,
}

/// Authorize handler，处理授权码流程。
pub struct AuthorizeHandler {
    store: Arc<dyn OAuth2ClientStore>,
    dao: Arc<dyn GarrisonDao>,
    login_url: String,
    /// consent 征询页 URL：记忆不足时升级重定向的目标；None 时升级路径以
    /// interaction_required 显性失败（fail-closed，不静默放行）。
    consent_url: Option<String>,
    /// 属性快照比较粒度（默认 ATTRIBUTE_NAME）。
    attribute_granularity: AttributeSnapshotGranularity,
}

impl AuthorizeHandler {
    /// 创建 handler。
    ///
    /// # 参数
    /// - `store`：OAuth2 客户端存储
    /// - `dao`：DAO（用于存储授权码 / 暂存票据 / consent 记忆）
    /// - `login_url`：未登录时重定向的登录页面 URL
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn GarrisonDao>,
        login_url: String,
    ) -> Self {
        Self {
            store,
            dao,
            login_url,
            consent_url: None,
            attribute_granularity: AttributeSnapshotGranularity::default(),
        }
    }

    /// 配置 consent 征询页 URL（consent 记忆不足时的升级重定向目标）。
    ///
    /// 未配置时，征询需求以 `interaction_required` 显性失败（不静默放行）。
    pub fn with_consent_url(mut self, consent_url: String) -> Self {
        self.consent_url = Some(consent_url);
        self
    }

    /// 配置属性快照比较粒度（默认 ATTRIBUTE_NAME）。
    pub fn with_attribute_granularity(mut self, granularity: AttributeSnapshotGranularity) -> Self {
        self.attribute_granularity = granularity;
        self
    }

    /// 处理 authorize 请求。
    ///
    /// # 参数
    /// - `req`：请求参数
    /// - `user_id`：已登录用户 ID（None 表示未登录）
    ///
    /// # 返回
    /// - `Ok(AuthorizeResponse::Redirect)`：授权成功，重定向到 redirect_uri
    /// - `Ok(AuthorizeResponse::LoginRequired)`：未登录，重定向到登录页
    ///   （return_to 携带续流票据，登录后经 [`AuthorizeHandler::resume`] 续流）
    /// - `Err`：请求参数错误（client_id 无效 / redirect_uri 不匹配 / PKCE 校验失败等）
    pub async fn authorize(
        &self,
        req: &AuthorizeRequest,
        user_id: Option<i64>,
    ) -> GarrisonResult<AuthorizeResponse> {
        self.authorize_with_prompt(req, user_id, AuthorizePrompt::None)
            .await
    }

    /// 处理带 prompt 语义的 authorize 请求。
    ///
    /// # 参数
    /// - `prompt`：OIDC Core §3.1.2.1 prompt 语义（none / login）
    pub async fn authorize_with_prompt(
        &self,
        req: &AuthorizeRequest,
        user_id: Option<i64>,
        prompt: AuthorizePrompt,
    ) -> GarrisonResult<AuthorizeResponse> {
        // 1. 校验 response_type / PKCE 方法 / challenge 非空
        validate_request_shape(req)?;

        // 2. 校验 client_id
        let client = self.load_client(&req.client_id).await?;

        // 3. 校验 redirect_uri 白名单
        if !client.is_redirect_uri_allowed(&req.redirect_uri) {
            return Err(GarrisonError::OAuth2(format!(
                "oauth2-server-authorize-redirect-uri-not-allowed::{}",
                req.redirect_uri
            )));
        }

        // 4. prompt=login（含别名变体）：已登录也强制重走登录往返（重新认证语义）
        if matches!(prompt, AuthorizePrompt::ForceLogin | AuthorizePrompt::Login) {
            return self.restage_and_login_redirect(req).await;
        }

        // 5. 检查用户登录状态
        let Some(user_id) = user_id else {
            // prompt=none：不弹登录——interaction_required 显性失败
            if prompt == AuthorizePrompt::NoInteraction {
                return Err(interaction_required_error());
            }
            // 两段式：校验通过后签发票据暂存完整请求，登录后凭票据续流
            return self.restage_and_login_redirect(req).await;
        };

        // 6. 解析 scope 并校验客户端白名单
        let scopes = parse_request_scopes(req);
        client.validate_scopes(&scopes)?;

        // 7. prompt=none：仅当 consent 记忆完整覆盖时直接放行
        if prompt == AuthorizePrompt::NoInteraction {
            let tenant_id = current_tenant_id_strict().unwrap_or(0);
            if self
                .consent_decision(tenant_id, user_id, &req.client_id, &scopes, &[])
                .await?
                != ConsentDecision::Remembered
            {
                return Err(interaction_required_error());
            }
            return self.issue_authorization_code(req, &scopes, user_id).await;
        }

        // 8. 授权续流（consent 记忆判定 + 授权码签发）
        // 直连 authorize 暂不携带属性视图（空视图快照），属性级重征询经
        // resume / resume_with_consent 路径生效
        self.continue_authorization(req, &scopes, user_id, &[])
            .await
    }

    /// 登录后凭票据续流：原子消费票据并恢复完整请求。
    ///
    /// 票据一次性（GETDEL 原子消费）：过期 / 未知 / 二次消费统一以
    /// `oauth2-server-authorize-ticket-invalid-or-expired` 拒绝，不区分三者
    /// （避免向票据持有者泄露票据状态）。
    ///
    /// # 参数
    /// - `ticket`：authorize 阶段签发的暂存票据
    /// - `user_id`：登录后的用户 ID；None 表示仍未登录——以新票据重新暂存
    ///   （旧票据已消费，一次性语义保持）并再次引导登录
    pub async fn resume(
        &self,
        ticket: &str,
        user_id: Option<i64>,
        attributes: &[ConsentAttributes],
    ) -> GarrisonResult<AuthorizeResponse> {
        let key = authorize_ticket_key(ticket);
        // 原子消费：读取 + 删除单次完成，并发二次消费只有一个能取到
        let json = self
            .dao
            .get_and_delete(&key)
            .await?
            .ok_or_else(ticket_invalid_error)?;
        let req: AuthorizeRequest = serde_json::from_str(&json).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-ticket-deserialize::{}", e))
        })?;

        let Some(user_id) = user_id else {
            return self.restage_and_login_redirect(&req).await;
        };

        // 恢复的请求必须 fail-closed 重校验（往返期间注册可能变化）
        let scopes = self.revalidate_staged(&req).await?;
        self.continue_authorization(&req, &scopes, user_id, attributes)
            .await
    }

    /// 以新票据重新暂存请求并构造登录页跳转地址。
    ///
    /// return_to 仅携带 resume 地址 + 票据：原始请求参数不进入 return_to，
    /// 参数注入面被票据化结构性消除。
    async fn restage_and_login_redirect(
        &self,
        req: &AuthorizeRequest,
    ) -> GarrisonResult<AuthorizeResponse> {
        let ticket = self.stage_request(req).await?;
        let return_to = format!("/oauth2/authorize/resume?ticket={}", ticket);
        let login_url = format!(
            "{}?return_to={}",
            self.login_url,
            utf8_percent_encode(&return_to, QUERY_VALUE_ENCODE_SET)
        );
        Ok(AuthorizeResponse::LoginRequired { login_url })
    }

    /// 将完整请求暂存为一次性票据（`set_if_absent`，TTL 600s），返回票据。
    async fn stage_request(&self, req: &AuthorizeRequest) -> GarrisonResult<String> {
        let ticket = generate_authorize_ticket();
        let key = authorize_ticket_key(&ticket);
        let json = serde_json::to_string(req).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-serialize::{}", e))
        })?;
        // SETNX：票据空间 62^32，冲突只可能是蓄意键复用——显性失败，绝不覆盖既有暂存
        if !self
            .dao
            .set_if_absent(&key, &json, AUTHORIZE_TICKET_TTL_SECONDS)
            .await?
        {
            return Err(GarrisonError::Internal(
                "oauth2-server-authorize-ticket-collision".into(),
            ));
        }
        Ok(ticket)
    }

    /// 登录上下文中的授权续流：consent 记忆判定 + 授权码签发。
    ///
    /// 调用方（直连 authorize / resume）负责客户端与 scope 的 fail-closed
    /// 重校验；本方法只做 consent 记忆决策与放行/升级。
    async fn continue_authorization(
        &self,
        req: &AuthorizeRequest,
        scopes: &[String],
        user_id: i64,
        attributes: &[ConsentAttributes],
    ) -> GarrisonResult<AuthorizeResponse> {
        let tenant_id = current_tenant_id_strict().unwrap_or(0);
        match self
            .consent_decision(tenant_id, user_id, &req.client_id, scopes, attributes)
            .await?
        {
            ConsentDecision::Remembered => {
                self.issue_authorization_code(req, scopes, user_id).await
            },
            ConsentDecision::Required(reason) => {
                // 首次授权沿用既有直连放行语义：静默批准并记录，后续授权进入
                // scope 超集记忆判定（不新增征询往返）
                if matches!(reason, ConsentRequiredReason::FirstGrant) {
                    self.grant_consent(tenant_id, user_id, &req.client_id, scopes, attributes)
                        .await?;
                    return self.issue_authorization_code(req, scopes, user_id).await;
                }
                // 记忆不足（扩 scope / 属性变化 / 记录损坏）：升级征询
                self.escalate_consent(req).await
            },
        }
    }

    /// consent 记忆不足时的征询升级：以新票据重新暂存并重定向征询页。
    async fn escalate_consent(&self, req: &AuthorizeRequest) -> GarrisonResult<AuthorizeResponse> {
        let Some(consent_url) = &self.consent_url else {
            // 未配置征询页：无法完成征询往返——显性失败，不静默放行
            return Err(interaction_required_error());
        };
        let ticket = self.stage_request(req).await?;
        // 征询页允许自带 query string：按是否已有 query 选定界符（同授权码重定向）
        let sep = if consent_url.contains('?') { '&' } else { '?' };
        let login_url = format!("{}{}ticket={}", consent_url, sep, ticket);
        Ok(AuthorizeResponse::LoginRequired { login_url })
    }

    /// 判定本次请求是否可由记忆的 consent 覆盖（免征询）。
    ///
    /// 判定序：记录存在性 → 记录可解析性（fail-safe）→ scope 超集 → 属性快照。
    ///
    /// # 参数
    /// - `tenant_id`：租户 ID（consent 键的第一段；授权续流路径取当前租户上下文，
    ///   无上下文时为默认租户 0）
    /// - `requested_scopes`：本次请求的 scope 集合
    /// - `attributes`：本次请求的属性视图（决定释放哪些属性 → 决定是否重新征询）
    pub async fn consent_decision(
        &self,
        tenant_id: i64,
        user_id: i64,
        client_id: &str,
        requested_scopes: &[String],
        attributes: &[ConsentAttributes],
    ) -> GarrisonResult<ConsentDecision> {
        let key = consent_key(tenant_id, user_id, client_id);
        let Some(json) = self.dao.get(&key).await? else {
            return Ok(ConsentDecision::Required(ConsentRequiredReason::FirstGrant));
        };
        // 记录不可解析（存储损坏 / 写入被截断 / 快照哈希缺失）：fail-safe
        // 重新征询，绝不静默放行
        let Ok(record) = serde_json::from_str::<ConsentRecord>(&json) else {
            return Ok(ConsentDecision::Required(
                ConsentRequiredReason::SnapshotUnreadable,
            ));
        };

        // scope 超集判定：请求 ⊆ 已授才可能免征询
        let new_scopes: Vec<String> = requested_scopes
            .iter()
            .filter(|s| !record.granted_scopes.contains(*s))
            .cloned()
            .collect();
        if !new_scopes.is_empty() {
            return Ok(ConsentDecision::Required(
                ConsentRequiredReason::ScopeExpansion { new_scopes },
            ));
        }

        // 属性快照判定：名哈希双粒度都比较；值哈希仅 ATTRIBUTE_VALUE 粒度参与。
        // 快照哈希缺失 / 非法（如读到了 scope-only 的旧格式记录）→ fail-safe 重征询
        let names_changed = record.attribute_names_hash != attribute_names_hash(attributes);
        let values_changed = record.attribute_values_hash != attribute_values_hash(attributes);
        let attributes_changed = match self.attribute_granularity {
            AttributeSnapshotGranularity::AttributeName => names_changed,
            AttributeSnapshotGranularity::AttributeValue => names_changed || values_changed,
        };
        if attributes_changed {
            return Ok(ConsentDecision::Required(
                ConsentRequiredReason::AttributesChanged,
            ));
        }

        Ok(ConsentDecision::Remembered)
    }

    /// 记录用户批准的 consent（超集合并 + 属性快照快照写入），返回合并后的已授集合。
    ///
    /// 合并语义：已授集合只增不减——本次批准的 scope 并入既有记录后回写。
    /// 记录不可解析时以本次批准重建（重建后仍需重新批准既有增量 scope，
    /// fail-safe 方向是多征询而非少征询）。记录永久驻留（consent 跨会话有效）。
    pub async fn grant_consent(
        &self,
        tenant_id: i64,
        user_id: i64,
        client_id: &str,
        approved_scopes: &[String],
        attributes: &[ConsentAttributes],
    ) -> GarrisonResult<Vec<String>> {
        let key = consent_key(tenant_id, user_id, client_id);
        let mut merged: Vec<String> = self
            .dao
            .get(&key)
            .await?
            .and_then(|json| serde_json::from_str::<ConsentRecord>(&json).ok())
            .map(|r| r.granted_scopes)
            .unwrap_or_default();
        for scope in approved_scopes {
            if !merged.contains(scope) {
                merged.push(scope.clone());
            }
        }
        merged.sort();
        // 属性快照以本次批准时的视图覆盖写入（cas update 语义：最新决策为准）
        let record = ConsentRecord {
            granted_scopes: merged.clone(),
            attribute_names_hash: attribute_names_hash(attributes),
            attribute_values_hash: attribute_values_hash(attributes),
        };
        let json = serde_json::to_string(&record).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-serialize::{}", e))
        })?;
        // TTL 0 = 永久驻留
        self.dao.set(&key, &json, 0).await?;
        Ok(merged)
    }

    /// consent 征询后的重入续流：消费升级时签发的新票据并落实用户决定。
    ///
    /// # 参数
    /// - `approved`：用户批准（true：scope 超集合并后放行）/ 拒绝（false：access_denied）
    /// - `attributes`：批准时的属性视图（随 consent 记录写入快照）
    pub async fn resume_with_consent(
        &self,
        ticket: &str,
        user_id: i64,
        approved: bool,
        attributes: &[ConsentAttributes],
    ) -> GarrisonResult<AuthorizeResponse> {
        let key = authorize_ticket_key(ticket);
        // 原子消费（同 resume：过期 / 二次消费统一拒绝）
        let json = self
            .dao
            .get_and_delete(&key)
            .await?
            .ok_or_else(ticket_invalid_error)?;
        let req: AuthorizeRequest = serde_json::from_str(&json).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-ticket-deserialize::{}", e))
        })?;

        if !approved {
            // RFC 6749 §4.1.2.1：用户拒绝授权
            return Err(GarrisonError::OAuth2(
                "oauth2-server-authorize-access-denied".into(),
            ));
        }

        let scopes = self.revalidate_staged(&req).await?;
        let tenant_id = current_tenant_id_strict().unwrap_or(0);
        self.grant_consent(tenant_id, user_id, &req.client_id, &scopes, attributes)
            .await?;
        self.issue_authorization_code(&req, &scopes, user_id).await
    }

    /// 往返后 fail-closed 重校验（客户端存在 / redirect_uri / scope 白名单），
    /// 返回解析后的 scope 集合。
    async fn revalidate_staged(&self, req: &AuthorizeRequest) -> GarrisonResult<Vec<String>> {
        let client = self.load_client(&req.client_id).await?;
        if !client.is_redirect_uri_allowed(&req.redirect_uri) {
            return Err(GarrisonError::OAuth2(format!(
                "oauth2-server-authorize-redirect-uri-not-allowed::{}",
                req.redirect_uri
            )));
        }
        let scopes = parse_request_scopes(req);
        client.validate_scopes(&scopes)?;
        Ok(scopes)
    }

    /// 生成授权码并构造重定向地址（10 分钟 TTL，一次性使用）。
    async fn issue_authorization_code(
        &self,
        req: &AuthorizeRequest,
        scopes: &[String],
        user_id: i64,
    ) -> GarrisonResult<AuthorizeResponse> {
        let code = generate_authorization_code();
        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            scopes: scopes.to_vec(),
            user_id,
            code_challenge: req.code_challenge.clone(),
        };

        let key = DaoKeyPrefix::OAuth2AuthCode.build_key(&code);
        let json = serde_json::to_string(&auth_code).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-serialize::{}", e))
        })?;
        self.dao.set(&key, &json, AUTH_CODE_TTL_SECONDS).await?;

        // redirect_uri 白名单为精确匹配，允许自带 query string（如
        // `https://app.example.com/cb?existing=param`）。RFC 6749 §4.1.2 /
        // RFC 3986：追加参数须按是否已有 query 选定界符（? 或 &），
        // 恒拼 `?` 会产生双 `?` 畸形 URL。
        let sep = if req.redirect_uri.contains('?') {
            '&'
        } else {
            '?'
        };
        let mut location = format!("{}{}code={}", req.redirect_uri, sep, code);
        if let Some(state) = &req.state {
            location.push_str("&state=");
            location.push_str(&utf8_percent_encode(state, QUERY_VALUE_ENCODE_SET).to_string());
        }
        Ok(AuthorizeResponse::Redirect { location })
    }

    /// 加载客户端（不存在 → 显性 OAuth2 错误）。
    async fn load_client(
        &self,
        client_id: &str,
    ) -> GarrisonResult<crate::oauth2_server::client::OAuth2Client> {
        self.store.get(client_id).await?.ok_or_else(|| {
            GarrisonError::OAuth2(format!("oauth2-server-client-id-invalid::{}", client_id))
        })
    }

    /// 消费授权码（一次性使用，原子消费：读取与删除为单次 DAO 操作）。
    ///
    /// 供 /oauth2/token 端点调用：授权码交换 access_token。
    ///
    /// 使用 `dao.get_and_delete` 将「读取 + 删除」合并为原子操作，消除
    /// `get` 与 `delete` 之间的 TOCTOU 竞态窗口（并发双花 / 重放攻击）：
    /// 多个并发请求同一 code 时，只有一个能原子地取到 `Some`，其余返回 `None`。
    ///
    /// # 返回
    /// - `Ok(Some(code))`：授权码有效，返回关联数据
    /// - `Ok(None)`：授权码不存在、已过期或已被消费（重放/并发双花）
    pub async fn consume_code(&self, code: &str) -> GarrisonResult<Option<AuthorizationCode>> {
        let key = DaoKeyPrefix::OAuth2AuthCode.build_key(code);
        // 原子消费：get_and_delete 在存储层一次性完成「读取并返回 + 删除」
        let json = self.dao.get_and_delete(&key).await?;
        match json {
            Some(json) => {
                let auth_code: AuthorizationCode = serde_json::from_str(&json).map_err(|e| {
                    GarrisonError::Internal(format!("oauth2-server-authorize-deserialize::{}", e))
                })?;
                Ok(Some(auth_code))
            },
            None => Ok(None),
        }
    }

    /// 记录授权码签发的 token，供「重放/双花」时吊销。
    ///
    /// 授权码被原子消费（删除）后，其签发的 access/refresh token 仍需可被定位吊销。
    /// 因此将 `access_token` / `refresh_token` 写入独立的 `oauth2:codeused:` 记录，
    /// 与授权码主体（已删除）解耦。TTL 取较长值以覆盖 token 生命周期。
    pub async fn record_code_tokens(
        &self,
        code: &str,
        access_token: &str,
        refresh_token: Option<&str>,
    ) -> GarrisonResult<()> {
        let key = DaoKeyPrefix::OAuth2CodeUsed.build_key(code);
        let record = CodeUsedRecord {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.map(|s| s.to_string()),
        };
        let json = serde_json::to_string(&record).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-serialize::{}", e))
        })?;
        self.dao
            .set(&key, &json, CODE_USED_RECORD_TTL_SECONDS)
            .await
    }

    /// 重放/双花检测：授权码已不存在时，吊销其此前签发的 token。
    ///
    /// 读取 `oauth2:codeused:` 记录，删除 access/refresh token 的 DAO 记录
    /// （使 introspection / refresh 失效）。best-effort：删除失败仅记录告警，不阻断主流程。
    ///
    /// # 返回
    /// - `Ok(true)`：存在该 code 的签发记录并已完成吊销
    /// - `Ok(false)`：无签发记录（code 从未成功签发过 token，纯随机重放）
    pub async fn revoke_replayed_code_tokens(&self, code: &str) -> GarrisonResult<bool> {
        let key = DaoKeyPrefix::OAuth2CodeUsed.build_key(code);
        let json = self.dao.get_and_delete(&key).await?;
        let Some(json) = json else {
            return Ok(false);
        };
        let record: CodeUsedRecord = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "revoke_replayed_code_tokens: failed to deserialize codeused record, skipping revocation");
                return Ok(false);
            },
        };
        // 吊销 access token（introspection / 资源服务器按 DAO 记录校验时失效）
        let at_key = DaoKeyPrefix::OAuth2AccessToken.build_key(&record.access_token);
        if let Err(e) = self.dao.delete(&at_key).await {
            tracing::warn!(error = %e, "revoke_replayed_code_tokens: failed to delete access token record");
        }
        // 吊销 refresh token（阻止后续 refresh 轮换）
        if let Some(rt) = &record.refresh_token {
            let rt_key = oauth2_refresh_token_key(rt);
            if let Err(e) = self.dao.delete(&rt_key).await {
                tracing::warn!(error = %e, "revoke_replayed_code_tokens: failed to delete refresh token record");
            }
        }
        Ok(true)
    }
}

// ============================================================================
// 请求校验与解析辅助
// ============================================================================

/// 校验请求形状：response_type / PKCE 方法 / challenge 非空（错误序与既有端点一致）。
fn validate_request_shape(req: &AuthorizeRequest) -> GarrisonResult<()> {
    if req.response_type != "code" {
        return Err(GarrisonError::OAuth2(format!(
            "oauth2-server-authorize-unsupported-response-type::{}",
            req.response_type
        )));
    }
    if req.code_challenge_method != "S256" {
        return Err(GarrisonError::OAuth2(format!(
            "oauth2-server-authorize-unsupported-code-challenge-method::{}",
            req.code_challenge_method
        )));
    }
    if req.code_challenge.is_empty() {
        return Err(GarrisonError::OAuth2(
            "oauth2-server-authorize-code-challenge-empty".into(),
        ));
    }
    Ok(())
}

/// 解析 scope 参数（空格分隔；缺省为空集）。
fn parse_request_scopes(req: &AuthorizeRequest) -> Vec<String> {
    req.scope
        .as_ref()
        .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
        .unwrap_or_default()
}

// ============================================================================
// PKCE 工具函数
// ============================================================================

/// 生成授权码（32 字节随机数 → BASE64URL 编码）。
fn generate_authorization_code() -> String {
    let mut bytes = [0u8; 32];
    // getrandom::fill 每次直接读 OS CSPRNG（系统调用），无用户态 DRBG 缓冲，
    // 相比 thread_rng 性能略低（~100-300ns vs ~10-30ns/调用），但消除 reseed 状态机攻击面。
    // 授权码生成非高频路径（每次用户授权一次），安全优先于性能。
    // 与项目其余模块（src/web/csrf.rs / src/account/credential/backup_code.rs 等）规范一致。
    getrandom::fill(&mut bytes).expect("OS CSPRNG 不可用");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 生成 authorize 暂存票据（32 字符字母数字随机串）。
///
/// ThreadRng（ChaCha12 CSPRNG，OS 熵播种）：票据是登录往返的请求暂存凭证，
/// 可预测性意味着攻击者可持他人票据恢复其 authorize 请求（会话固定面）。
impl AuthorizeHandler {
    /// 启动期 reconcile：清理引用了已删除 client 的 consent 行。
    ///
    /// 以 client store 的存活列表为准——consent 键 `{prefix}{tenant}:{user}:{client}`
    /// 逐条扫描（`keys("oauth2:consent:*")`），client 已不存在即删除；
    /// 返回 (removed, kept)。幂等：再跑一次 removed == 0。
    pub async fn reconcile_consents(&self) -> GarrisonResult<(usize, usize)> {
        let alive: std::collections::HashSet<String> = self
            .store
            .list()
            .await?
            .into_iter()
            .map(|c| c.client_id)
            .collect();
        let pattern = format!("{OAUTH2_CONSENT_KEY_PREFIX}*");
        let mut removed = 0;
        let mut kept = 0;
        for key in self.dao.keys(&pattern).await? {
            let Some(rest) = key.strip_prefix(OAUTH2_CONSENT_KEY_PREFIX) else {
                continue;
            };
            // rest = `{tenant}:{user}:{client_id}`（client_id 不含 ':'，
            // 与 consent_key 构造一致）；取最后一段为 client_id
            let Some((_, client_id)) = rest.rsplit_once(':') else {
                continue;
            };
            if alive.contains(client_id) {
                kept += 1;
            } else {
                self.dao.delete(&key).await?;
                removed += 1;
            }
        }
        Ok((removed, kept))
    }
}

fn generate_authorize_ticket() -> String {
    use rand::distr::{Alphanumeric, SampleString};
    Alphanumeric.sample_string(&mut rand::rng(), AUTHORIZE_TICKET_LEN)
}

// ============================================================================
// 属性快照哈希（对齐 cas DefaultConsentDecisionBuilder 的双粒度判定）
// ============================================================================

/// SHA-512 摘要的小写十六进制编码（128 字符）。
fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// 属性名集合哈希：属性名排序后以 `|` 连接取 SHA-512（对齐
/// cas sha512ConsentAttributeNames 的 `String.join("|", keySet)`）。
///
/// 排序保证判定与属性出现顺序无关；双粒度（名/值）都参与该比较。
fn attribute_names_hash(attributes: &[ConsentAttributes]) -> String {
    let mut names: Vec<&str> = attributes.iter().map(|(name, _)| name.as_str()).collect();
    names.sort();
    sha512_hex(names.join("|").as_bytes())
}

/// 属性值哈希：按属性名排序后，各属性的值序列以 `|` 连接取 SHA-512
///（对齐 cas sha512ConsentAttributeValues 的值聚合）。仅 ATTRIBUTE_VALUE
/// 粒度参与比较。
fn attribute_values_hash(attributes: &[ConsentAttributes]) -> String {
    let mut sorted: Vec<&ConsentAttributes> = attributes.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let per_attr: Vec<String> = sorted.iter().map(|(_, values)| values.join("")).collect();
    sha512_hex(per_attr.join("|").as_bytes())
}

/// 从 code_verifier 生成 code_challenge（S256 方法）。
///
/// `code_challenge = BASE64URL(SHA256(code_verifier))`
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

/// 校验 code_verifier 长度（RFC 7636 §4.1：43-128 字符）。
pub fn is_valid_code_verifier_len(code_verifier: &str) -> bool {
    (CODE_VERIFIER_MIN_LEN..=CODE_VERIFIER_MAX_LEN).contains(&code_verifier.len())
}

/// 校验 code_verifier 与 code_challenge 是否匹配（S256 方法）。
///
/// 1. 校验 code_verifier 长度（43-128 字符）
/// 2. 校验 code_challenge 长度（S256 固定 43 字符，防止 DoS）
/// 3. 计算 SHA256(code_verifier) → BASE64URL
/// 4. 与 code_challenge 常量时间比对（CWE-208 防御）
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> GarrisonResult<bool> {
    if !is_valid_code_verifier_len(code_verifier) {
        return Err(GarrisonError::OAuth2(format!(
            "oauth2-server-authorize-code-verifier-invalid-length::{}",
            code_verifier.len()
        )));
    }
    // 长度校验：S256 challenge = BASE64URL_NO_PAD(SHA256) 固定 43 字符。
    // 异常长度直接判失败（Ok(false)），避免进入常量时间循环被超长输入放大成 CPU DoS。
    if code_challenge.len() != S256_CHALLENGE_LEN {
        return Ok(false);
    }
    let computed = generate_code_challenge(code_verifier);
    // 纵深防御：常量时间比较，与代码库其余签名比较保持一致（CWE-208）。
    Ok(crate::secure::ct_eq::constant_time_eq(
        computed.as_bytes(),
        code_challenge.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;
    use crate::oauth2_server::client::{GrantType, OAuth2Client};

    /// 创建测试用 OAuth2Client。
    fn make_test_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap()
    }

    /// 创建测试用 AuthorizeHandler。
    fn make_handler() -> (AuthorizeHandler, Arc<InMemoryDao>) {
        let dao = Arc::new(InMemoryDao::new());
        let store = Arc::new(crate::oauth2_server::client::DaoOAuth2ClientStore::new(
            dao.clone(),
        ));
        let handler =
            AuthorizeHandler::new(store, dao.clone(), "https://auth.example.com/login".into());
        (handler, dao)
    }

    /// 创建测试用 AuthorizeRequest。
    fn make_request(client_id: &str, code_challenge: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("xyz".into()),
            code_challenge: code_challenge.into(),
            code_challenge_method: "S256".into(),
        }
    }

    // === PKCE 工具函数测试 ===

    #[test]
    fn generate_code_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B 测试向量
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(generate_code_challenge(verifier), expected);
    }

    #[test]
    fn verify_pkce_matches() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        assert!(verify_pkce(verifier, &challenge).unwrap());
    }

    #[test]
    fn verify_pkce_mismatch() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        // 使用不同的 verifier 生成 challenge
        let other = generate_code_challenge("other-verifier-other-verifier-other-verifier");
        assert!(!verify_pkce(verifier, &other).unwrap());
        let _ = wrong_challenge;
    }

    #[test]
    fn verify_pkce_rejects_short_verifier() {
        let err = verify_pkce("short", "challenge").unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[test]
    fn verify_pkce_rejects_long_verifier() {
        let verifier = "a".repeat(129);
        let err = verify_pkce(&verifier, "challenge").unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[test]
    fn is_valid_code_verifier_len_boundary() {
        assert!(!is_valid_code_verifier_len(&"a".repeat(42)));
        assert!(is_valid_code_verifier_len(&"a".repeat(43)));
        assert!(is_valid_code_verifier_len(&"a".repeat(128)));
        assert!(!is_valid_code_verifier_len(&"a".repeat(129)));
    }

    // === authorize handler 测试 ===

    #[tokio::test]
    async fn authorize_success() {
        let (handler, _) = make_handler();
        let client = make_test_client("auth-001");
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("auth-001", &challenge);

        let resp = handler.authorize(&req, Some(1001)).await.expect("授权");
        match resp {
            AuthorizeResponse::Redirect { location } => {
                assert!(location.starts_with("https://app.example.com/cb?code="));
                assert!(location.contains("state=xyz"));
            },
            _ => panic!("期望 Redirect"),
        }
    }

    #[tokio::test]
    async fn authorize_unlogged_redirects_to_login() {
        let (handler, _) = make_handler();
        let client = make_test_client("auth-002");
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("auth-002", &challenge);

        let resp = handler.authorize(&req, None).await.expect("授权");
        match resp {
            AuthorizeResponse::LoginRequired { login_url } => {
                assert!(login_url.starts_with("https://auth.example.com/login?return_to="));
            },
            _ => panic!("期望 LoginRequired"),
        }
    }

    #[tokio::test]
    async fn authorize_invalid_client_id() {
        let (handler, _) = make_handler();
        let req = make_request("no-such-client", "challenge");
        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_invalid_redirect_uri() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-003"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-003", &challenge);
        req.redirect_uri = "https://evil.example.com/cb".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_unsupported_response_type() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-004"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-004", &challenge);
        req.response_type = "token".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_unsupported_code_challenge_method() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-005"))
            .await
            .unwrap();

        let req = make_request("auth-005", "challenge");
        // 修改 method 为 plain
        let mut req = req;
        req.code_challenge_method = "plain".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_empty_code_challenge() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-006"))
            .await
            .unwrap();

        let req = make_request("auth-006", "");
        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_without_state() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-007"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-007", &challenge);
        req.state = None;

        let resp = handler.authorize(&req, Some(1)).await.unwrap();
        match resp {
            AuthorizeResponse::Redirect { location } => {
                assert!(!location.contains("state="));
            },
            _ => panic!("期望 Redirect"),
        }
    }

    /// 两段式票据化后，未登录 return_to 只携带 resume 地址与一次性票据，
    /// 原始请求参数（含 redirect_uri 的 `&`/`=`、state 的特殊字符）不再进入
    /// return_to——参数注入面被票据化结构性消除。
    #[tokio::test]
    async fn authorize_return_to_carries_only_resume_ticket() {
        let (handler, dao) = make_handler();
        // 注册一个允许特殊 redirect_uri 的客户端
        let client = OAuth2Client::new(
            "auth-encode-001",
            "secret-123",
            vec!["https://app.example.com/cb?existing=param".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap();
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = AuthorizeRequest {
            response_type: "code".into(),
            client_id: "auth-encode-001".into(),
            redirect_uri: "https://app.example.com/cb?existing=param".into(),
            scope: Some("read".into()),
            state: Some("state&with&amps".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };

        let resp = handler
            .authorize(&req, None)
            .await
            .expect("应返回 LoginRequired");
        match resp {
            AuthorizeResponse::LoginRequired { login_url } => {
                let return_to_part = login_url
                    .split("return_to=")
                    .nth(1)
                    .expect("应包含 return_to 参数");
                // return_to 必须指向 resume 地址，且只携带票据——
                // redirect_uri / state 等原始参数不得以任何编码形式出现
                assert!(
                    return_to_part.contains("authorize%2Fresume")
                        || return_to_part.contains("authorize/resume"),
                    "return_to 应指向 resume 续流地址: {}",
                    login_url
                );
                assert!(
                    !return_to_part.contains("redirect_uri"),
                    "return_to 不得携带 redirect_uri（票据化后由暂存恢复）: {}",
                    login_url
                );
                assert!(
                    !return_to_part.contains("state"),
                    "return_to 不得携带 state: {}",
                    login_url
                );
                // 票据本身应为 32 字符字母数字
                let ticket = return_to_part
                    .rsplit("ticket%3D")
                    .next()
                    .or_else(|| return_to_part.rsplit("ticket=").next())
                    .expect("return_to 应携带票据参数");
                assert_eq!(
                    ticket.len(),
                    32,
                    "票据应为 32 字符，实际 {} 字符: {}",
                    ticket.len(),
                    login_url
                );
                assert!(
                    ticket.chars().all(|c| c.is_ascii_alphanumeric()),
                    "票据应为纯字母数字: {}",
                    login_url
                );
                // 暂存票据应可从 DAO 中定位（TTL 由 stage 路径写入）
                let staged = dao
                    .keys("oauth2:authorize-ticket:*")
                    .await
                    .expect("keys 扫描");
                assert_eq!(staged.len(), 1, "应恰好暂存一张票据");
            },
            _ => panic!("期望 LoginRequired"),
        }
    }

    /// 未登录 authorize：请求校验通过后签发 32 字符票据，
    /// 经 DAO `set_if_absent` 暂存完整请求（TTL 600s）。
    #[tokio::test]
    async fn authorize_not_logged_in_stages_full_request_with_600s_ttl() {
        let (handler, dao) = make_handler();
        handler
            .store
            .create(make_test_client("ticket-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("ticket-001", &challenge);

        let resp = handler.authorize(&req, None).await.expect("授权");
        let login_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };

        let staged = dao
            .keys("oauth2:authorize-ticket:*")
            .await
            .expect("keys 扫描");
        assert_eq!(staged.len(), 1, "应恰好暂存一张票据");
        let key = &staged[0];

        // 暂存内容必须完整覆盖原始请求参数（resume 恢复完整请求的前提）
        let json = dao.get(key).await.unwrap().expect("暂存应存在");
        let staged_req: AuthorizeRequest = serde_json::from_str(&json).expect("应可反序列化");
        assert_eq!(staged_req.client_id, req.client_id);
        assert_eq!(staged_req.redirect_uri, req.redirect_uri);
        assert_eq!(staged_req.scope, req.scope);
        assert_eq!(staged_req.state, req.state);
        assert_eq!(staged_req.code_challenge, req.code_challenge);
        assert_eq!(staged_req.response_type, req.response_type);
        assert_eq!(staged_req.code_challenge_method, req.code_challenge_method);

        // TTL 必须为 600s 量级（10 分钟，对齐 tinyauth 暂存窗口）
        let ttl = dao.get_timeout(key).await.unwrap().expect("应设置 TTL");
        assert!(
            ttl.as_secs() <= 600 && ttl.as_secs() > 590,
            "TTL 应为 600s 量级，实际 {:?}",
            ttl
        );

        // return_to 指向 resume 地址且票据与暂存键一致
        let ticket = extract_ticket_from_login_url(&login_url);
        assert_eq!(
            key,
            &format!("oauth2:authorize-ticket:{}", ticket),
            "return_to 中的票据应与暂存键一致: {}",
            login_url
        );
    }

    /// 登录后凭票据 resume：原子消费票据，恢复完整请求并续流签发授权码——
    /// code 的 client/redirect_uri/scope/challenge 均来自暂存的原始请求。
    #[tokio::test]
    async fn resume_restores_full_request_and_issues_code() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("ticket-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("ticket-002", &challenge);

        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let ticket = extract_ticket_from_login_url(&login_url);

        // 登录完成后凭票据续流（登录后 user_id 就位）
        let resp = handler
            .resume(&ticket, Some(4001), &[])
            .await
            .expect("resume");
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        assert!(location.contains("state=xyz"), "state 应原样回传");

        // code 必须携带暂存请求的全部上下文
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let auth_code = handler.consume_code(code).await.unwrap().expect("应存在");
        assert_eq!(auth_code.client_id, "ticket-002");
        assert_eq!(auth_code.user_id, 4001);
        assert_eq!(auth_code.redirect_uri, "https://app.example.com/cb");
        assert_eq!(auth_code.scopes, vec!["read".to_string()]);
        assert_eq!(auth_code.code_challenge, challenge);
    }

    /// 未知 / 过期票据 resume 拒绝（显性 OAuth2 错误，不静默当作新请求）。
    #[tokio::test]
    async fn resume_rejects_unknown_or_expired_ticket() {
        let (handler, _) = make_handler();
        let err = handler
            .resume("totally-unknown-ticket-0123456789ab", Some(1), &[])
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-ticket-invalid-or-expired"),
            "期望票据无效/过期错误，实际: {}",
            err
        );
    }

    /// 票据一次性：resume 成功后同一票据再次 resume 必须拒绝（二次消费拒）。
    #[tokio::test]
    async fn resume_rejects_second_consumption_of_same_ticket() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("ticket-003"))
            .await
            .unwrap();
        let req = make_request(
            "ticket-003",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );

        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let ticket = extract_ticket_from_login_url(&login_url);

        assert!(handler.resume(&ticket, Some(4002), &[]).await.is_ok());
        let err = handler.resume(&ticket, Some(4002), &[]).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-ticket-invalid-or-expired"),
            "二次消费应拒绝，实际: {}",
            err
        );
    }

    /// 票据 TTL 到期后 resume 拒绝（真实过期路径，非仅未知票据）。
    #[tokio::test]
    async fn resume_rejects_ticket_after_ttl_expiry() {
        let (handler, dao) = make_handler();
        // 手工暂存 1s TTL 的请求快照，模拟已发出的票据进入过期
        let req = make_request("ticket-004", "challenge");
        let json = serde_json::to_string(&req).unwrap();
        let key = "oauth2:authorize-ticket:expiring-ticket-0123456789012345";
        assert!(dao.set_if_absent(key, &json, 1).await.unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let ticket = key.rsplit(':').next().unwrap();
        let err = handler.resume(ticket, Some(4003), &[]).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-ticket-invalid-or-expired"),
            "过期票据应拒绝，实际: {}",
            err
        );
    }

    /// resume 时仍未登录：以新票据重新暂存（旧票据已消费，一次性语义保持），再次引导登录。
    #[tokio::test]
    async fn resume_without_login_reissues_fresh_ticket() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("ticket-005"))
            .await
            .unwrap();
        let req = make_request(
            "ticket-005",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );

        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let first_ticket = extract_ticket_from_login_url(&login_url);

        let resp = handler.resume(&first_ticket, None, &[]).await.unwrap();
        let second_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let second_ticket = extract_ticket_from_login_url(&second_url);
        assert_ne!(
            first_ticket, second_ticket,
            "重新暂存必须签发新票据（旧票据已消费）"
        );

        // 旧票据已消费；新票据可正常续流
        assert!(handler
            .resume(&first_ticket, Some(4004), &[])
            .await
            .is_err());
        assert!(handler
            .resume(&second_ticket, Some(4004), &[])
            .await
            .is_ok());
    }

    /// 从 LoginRequired 的 login_url 中提取票据（测试辅助：return_to=...ticket=...）。
    fn extract_ticket_from_login_url(login_url: &str) -> String {
        let return_to = login_url.split("return_to=").nth(1).expect("含 return_to");
        let decoded = percent_encoding::percent_decode_str(return_to)
            .decode_utf8()
            .expect("return_to 应为合法 UTF-8");
        decoded
            .rsplit("ticket=")
            .next()
            .expect("return_to 应含 ticket")
            .to_string()
    }

    /// 创建测试用 OAuth2Client（指定 allowed_scopes）。
    fn make_test_client_with_scopes(id: &str, scopes: &[&str]) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            scopes.iter().map(|s| s.to_string()).collect(),
        )
        .unwrap()
    }

    /// 创建带 consent 征询页配置的测试用 AuthorizeHandler。
    fn make_handler_with_consent_url() -> (AuthorizeHandler, Arc<InMemoryDao>) {
        let (handler, dao) = make_handler();
        let handler = handler.with_consent_url("https://auth.example.com/consent".into());
        (handler, dao)
    }

    // === consent 记忆测试 ===

    /// grant_consent 超集合并：已授集合只增不减，字典序持久化。
    #[tokio::test]
    async fn grant_consent_merges_superset_and_only_grows() {
        let (handler, dao) = make_handler();

        let merged = handler
            .grant_consent(0, 5001, "consent-001", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(merged, vec!["read".to_string()]);

        let merged = handler
            .grant_consent(
                0,
                5001,
                "consent-001",
                &["write".into(), "read".into()],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(merged, vec!["read".to_string(), "write".to_string()]);

        // 再次只授 read：既有 write 不得丢失（只增不减）
        let merged = handler
            .grant_consent(0, 5001, "consent-001", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(merged, vec!["read".to_string(), "write".to_string()]);

        // 持久化：键 (tenant, user, client) 的记录存在
        let key = "oauth2:consent:0:5001:consent-001";
        assert!(
            dao.get(key).await.unwrap().is_some(),
            "consent 记录应持久化于 (tenant,user,client) 键"
        );
    }

    /// scope 子集 ⊆ 已授 → 免征询（Remembered）。
    #[tokio::test]
    async fn consent_decision_subset_of_granted_is_remembered() {
        let (handler, _) = make_handler();
        handler
            .grant_consent(
                0,
                5002,
                "consent-002",
                &["read".into(), "write".into()],
                &[],
            )
            .await
            .unwrap();

        let d = handler
            .consent_decision(0, 5002, "consent-002", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(d, ConsentDecision::Remembered, "子集请求应免征询");
    }

    /// 含新增 scope → 重新征询，且原因中列出未授的增量 scope。
    #[tokio::test]
    async fn consent_decision_new_scope_requires_consent_listing_new_scopes() {
        let (handler, _) = make_handler();
        handler
            .grant_consent(0, 5003, "consent-003", &["read".into()], &[])
            .await
            .unwrap();

        let d = handler
            .consent_decision(
                0,
                5003,
                "consent-003",
                &["read".into(), "admin".into()],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::ScopeExpansion {
                new_scopes: vec!["admin".to_string()],
            }),
            "新增 scope 应触发重征询并列出增量"
        );
    }

    /// 无记录 → 首次授权需征询（FirstGrant）。
    #[tokio::test]
    async fn consent_decision_without_record_requires_first_grant() {
        let (handler, _) = make_handler();
        let d = handler
            .consent_decision(0, 5004, "consent-004", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::FirstGrant),
            "无记录应为首次授权"
        );
    }

    /// consent 记录按租户隔离：同 (user, client) 在不同 tenant 下互不可见。
    #[tokio::test]
    async fn consent_records_are_tenant_scoped() {
        let (handler, _) = make_handler();
        handler
            .grant_consent(7, 5005, "consent-005", &["read".into()], &[])
            .await
            .unwrap();

        let d = handler
            .consent_decision(7, 5005, "consent-005", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(d, ConsentDecision::Remembered);

        let d = handler
            .consent_decision(8, 5005, "consent-005", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::FirstGrant),
            "其他租户不得命中本租户 consent"
        );
    }

    /// 授权续流：consent 记忆不足（扩 scope）→ 升级征询页（新票据重入）；
    /// 批准后超集合并并放行。
    #[tokio::test]
    async fn resume_with_insufficient_consent_escalates_then_merge_on_approval() {
        let (handler, dao) = make_handler_with_consent_url();
        handler
            .store
            .create(make_test_client_with_scopes(
                "consent-006",
                &["read", "admin"],
            ))
            .await
            .unwrap();
        handler
            .grant_consent(0, 5006, "consent-006", &["read".into()], &[])
            .await
            .unwrap();

        // 请求含新增 scope：stage → resume → 升级征询页
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut req = make_request("consent-006", &generate_code_challenge(verifier));
        req.scope = Some("read admin".into());
        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let resp = handler
            .resume(&extract_ticket_from_login_url(&login_url), Some(5006), &[])
            .await
            .unwrap();
        let consent_page_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            other => panic!("期望升级征询页，实际: {:?}", other),
        };
        assert!(
            consent_page_url.starts_with("https://auth.example.com/consent?ticket="),
            "应重定向到征询页并携带重入票据: {}",
            consent_page_url
        );

        // 升级以新票据重入（一次性行为保持）
        let staged = dao
            .keys("oauth2:authorize-ticket:*")
            .await
            .expect("keys 扫描");
        assert_eq!(staged.len(), 1, "升级应签发恰好一张重入票据");

        // 批准：合并 consent 并放行
        let new_ticket = consent_page_url.rsplit("ticket=").next().unwrap();
        let resp = handler
            .resume_with_consent(new_ticket, 5006, true, &[])
            .await
            .unwrap();
        assert!(
            matches!(resp, AuthorizeResponse::Redirect { .. }),
            "批准后应放行"
        );

        // 合并后集合为超集：再次等价请求免征询
        let d = handler
            .consent_decision(
                0,
                5006,
                "consent-006",
                &["read".into(), "admin".into()],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(d, ConsentDecision::Remembered, "批准后应合并为超集");
    }

    /// 用户拒绝：access_denied 显性失败，consent 记录不发生变化。
    #[tokio::test]
    async fn resume_with_consent_denied_is_access_denied_and_records_nothing() {
        let (handler, _) = make_handler_with_consent_url();
        handler
            .store
            .create(make_test_client_with_scopes(
                "consent-007",
                &["read", "admin"],
            ))
            .await
            .unwrap();
        handler
            .grant_consent(0, 5007, "consent-007", &["read".into()], &[])
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut req = make_request("consent-007", &generate_code_challenge(verifier));
        req.scope = Some("read admin".into());
        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let resp = handler
            .resume(&extract_ticket_from_login_url(&login_url), Some(5007), &[])
            .await
            .unwrap();
        let consent_page_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            other => panic!("期望升级征询页，实际: {:?}", other),
        };
        let new_ticket = consent_page_url.rsplit("ticket=").next().unwrap();

        let err = handler
            .resume_with_consent(new_ticket, 5007, false, &[])
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-access-denied"),
            "拒绝应为 access_denied，实际: {}",
            err
        );

        // 记录未变：原 scope 仍 Remembered，增量 scope 仍需征询
        let d = handler
            .consent_decision(0, 5007, "consent-007", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(d, ConsentDecision::Remembered);
        let d = handler
            .consent_decision(
                0,
                5007,
                "consent-007",
                &["read".into(), "admin".into()],
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::ScopeExpansion { .. })
        ));
    }

    /// 未配置征询页且 consent 不足：interaction_required 显性失败（不静默放行）。
    #[tokio::test]
    async fn continue_without_consent_url_errors_explicitly_when_escalation_needed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client_with_scopes(
                "consent-008",
                &["read", "admin"],
            ))
            .await
            .unwrap();
        handler
            .grant_consent(0, 5008, "consent-008", &["read".into()], &[])
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut req = make_request("consent-008", &generate_code_challenge(verifier));
        req.scope = Some("read admin".into());
        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let err = handler
            .resume(&extract_ticket_from_login_url(&login_url), Some(5008), &[])
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-interaction-required"),
            "未配置征询页应显性失败，实际: {}",
            err
        );
    }

    /// 直连首次授权沿用既有放行语义：签发授权码并记录 consent；
    /// 后续同 scope 授权走记忆 fast path（免征询）。
    #[tokio::test]
    async fn authorize_direct_first_grant_records_consent_then_remembered() {
        let (handler, dao) = make_handler();
        handler
            .store
            .create(make_test_client("consent-009"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let req = make_request("consent-009", &generate_code_challenge(verifier));

        // 首次：放行 + 记录
        let resp = handler.authorize(&req, Some(6001)).await.unwrap();
        assert!(matches!(resp, AuthorizeResponse::Redirect { .. }));
        let key = "oauth2:consent:0:6001:consent-009";
        assert!(
            dao.get(key).await.unwrap().is_some(),
            "首次授权应记录 consent"
        );

        // 二次：记忆覆盖，免征询直接放行
        let resp = handler.authorize(&req, Some(6001)).await.unwrap();
        assert!(matches!(resp, AuthorizeResponse::Redirect { .. }));
    }

    // === 属性快照双粒度测试 ===

    /// 属性名集合变化 → 重新征询（ATTRIBUTE_NAME 粒度即比名哈希）。
    #[tokio::test]
    async fn attribute_name_change_requires_reconsent() {
        let (handler, _) = make_handler();
        let attrs = vec![("email".to_string(), vec!["a@x".to_string()])];
        handler
            .grant_consent(0, 7001, "attr-001", &["read".into()], &attrs)
            .await
            .unwrap();

        // 同属性视图 → 免征询
        let d = handler
            .consent_decision(0, 7001, "attr-001", &["read".into()], &attrs)
            .await
            .unwrap();
        assert_eq!(d, ConsentDecision::Remembered);

        // 属性名集合变化（新增 uid）→ 重征询
        let mut changed = attrs.clone();
        changed.push(("uid".to_string(), vec!["u1".to_string()]));
        let d = handler
            .consent_decision(0, 7001, "attr-001", &["read".into()], &changed)
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::AttributesChanged),
            "属性名集合变化应触发重征询"
        );
    }

    /// 属性值变化：ATTRIBUTE_VALUE 粒度重征询；ATTRIBUTE_NAME 粒度不触发（只比名）。
    #[tokio::test]
    async fn attribute_value_change_depends_on_granularity() {
        let attrs_old = vec![("email".to_string(), vec!["a@x".to_string()])];
        let attrs_new = vec![("email".to_string(), vec!["b@x".to_string()])];

        // 默认粒度（ATTRIBUTE_NAME）：值变不触发
        let (handler, _) = make_handler();
        handler
            .grant_consent(0, 7002, "attr-002", &["read".into()], &attrs_old)
            .await
            .unwrap();
        let d = handler
            .consent_decision(0, 7002, "attr-002", &["read".into()], &attrs_new)
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Remembered,
            "名哈希粒度下属性值变化不应重征询"
        );

        // ATTRIBUTE_VALUE 粒度：值变触发（粒度可配的直接体现）
        let (handler, _) = make_handler();
        let handler =
            handler.with_attribute_granularity(AttributeSnapshotGranularity::AttributeValue);
        handler
            .grant_consent(0, 7003, "attr-003", &["read".into()], &attrs_old)
            .await
            .unwrap();
        let d = handler
            .consent_decision(0, 7003, "attr-003", &["read".into()], &attrs_new)
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::AttributesChanged),
            "值哈希粒度下属性值变化应触发重征询"
        );
    }

    /// 属性不变：双粒度均免征询。
    #[tokio::test]
    async fn attribute_unchanged_remembered_under_both_granularities() {
        let attrs = vec![
            ("email".to_string(), vec!["a@x".to_string()]),
            ("uid".to_string(), vec!["u1".to_string(), "u2".to_string()]),
        ];
        for granularity in [
            AttributeSnapshotGranularity::AttributeName,
            AttributeSnapshotGranularity::AttributeValue,
        ] {
            let (handler, _) = make_handler();
            let handler = handler.with_attribute_granularity(granularity);
            handler
                .grant_consent(0, 7004, "attr-004", &["read".into()], &attrs)
                .await
                .unwrap();
            let d = handler
                .consent_decision(0, 7004, "attr-004", &["read".into()], &attrs)
                .await
                .unwrap();
            assert_eq!(
                d,
                ConsentDecision::Remembered,
                "{:?} 粒度下属性不变应免征询",
                granularity
            );
        }
    }

    /// consent 记录损坏（不可解析）→ fail-safe 重新征询（绝不静默放行）。
    #[tokio::test]
    async fn corrupt_consent_record_failsafe_requires_reconsent() {
        let (handler, dao) = make_handler();
        dao.set("oauth2:consent:0:7005:attr-005", "{broken-json", 0)
            .await
            .unwrap();
        let d = handler
            .consent_decision(0, 7005, "attr-005", &["read".into()], &[])
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::SnapshotUnreadable),
            "记录不可解析应 fail-safe 重征询"
        );
    }

    /// 快照哈希属性：SHA-512 十六进制（128 字符）、确定性、顺序不敏感；
    /// 名哈希只反映名集合（值变化不影响），值哈希对值差异敏感。
    #[test]
    fn attribute_snapshot_hash_properties() {
        let a = vec![
            ("email".to_string(), vec!["a@x".to_string()]),
            ("uid".to_string(), vec!["u1".to_string()]),
        ];
        let a_reordered = vec![
            ("uid".to_string(), vec!["u1".to_string()]),
            ("email".to_string(), vec!["a@x".to_string()]),
        ];
        // 与 a 仅值不同（名集合一致）
        let value_changed = vec![
            ("email".to_string(), vec!["b@x".to_string()]),
            ("uid".to_string(), vec!["u1".to_string()]),
        ];
        // 与 a 名集合不同
        let name_changed = vec![("email".to_string(), vec!["a@x".to_string()])];

        for hash_fn in [attribute_names_hash, attribute_values_hash] {
            let h1 = hash_fn(&a);
            assert_eq!(h1.len(), 128, "SHA-512 十六进制应为 128 字符");
            assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(h1, hash_fn(&a), "同输入哈希必须确定");
            assert_eq!(h1, hash_fn(&a_reordered), "输入顺序不得影响哈希");
        }
        // 名哈希：值变化不影响、名集合变化敏感
        assert_eq!(
            attribute_names_hash(&a),
            attribute_names_hash(&value_changed),
            "名哈希不得受属性值影响"
        );
        assert_ne!(
            attribute_names_hash(&a),
            attribute_names_hash(&name_changed),
            "名哈希必须反映名集合差异"
        );
        // 值哈希：值差异敏感
        assert_ne!(
            attribute_values_hash(&a),
            attribute_values_hash(&value_changed),
            "值哈希必须反映属性值差异"
        );
    }

    /// 征询批准路径携带属性视图：快照随批准写入，后续同视图请求免征询；
    /// 视图漂移触发重征询（fail-safe 方向是多征询）。
    #[tokio::test]
    async fn consent_approval_persists_attribute_snapshot() {
        let (handler, _) = make_handler_with_consent_url();
        handler
            .store
            .create(make_test_client_with_scopes("attr-006", &["read", "admin"]))
            .await
            .unwrap();
        handler
            .grant_consent(0, 7006, "attr-006", &["read".into()], &[])
            .await
            .unwrap();

        let attrs = vec![("email".to_string(), vec!["a@x".to_string()])];
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut req = make_request("attr-006", &generate_code_challenge(verifier));
        req.scope = Some("read admin".into());
        let login_url = match handler.authorize(&req, None).await.unwrap() {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            _ => panic!("期望 LoginRequired"),
        };
        let resp = handler
            .resume(
                &extract_ticket_from_login_url(&login_url),
                Some(7006),
                &attrs,
            )
            .await
            .unwrap();
        let consent_page_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            other => panic!("期望升级征询页，实际: {:?}", other),
        };
        let new_ticket = consent_page_url.rsplit("ticket=").next().unwrap();
        handler
            .resume_with_consent(new_ticket, 7006, true, &attrs)
            .await
            .unwrap();

        // 同属性视图 → 免征询
        let d = handler
            .consent_decision(
                0,
                7006,
                "attr-006",
                &["read".into(), "admin".into()],
                &attrs,
            )
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Remembered,
            "批准时的属性快照应覆盖后续同视图请求"
        );

        /// 属性视图漂移 → 重征询
        let d = handler
            .consent_decision(0, 7006, "attr-006", &["read".into(), "admin".into()], &[])
            .await
            .unwrap();
        assert_eq!(
            d,
            ConsentDecision::Required(ConsentRequiredReason::AttributesChanged),
            "属性视图漂移应触发重征询"
        );
    }

    // === reconcile + prompt=none 测试 ===

    /// 启动 reconcile：清理引用了已删除 client 的 consent 行，
    /// 存活 client 的记录原样保留。
    #[tokio::test]
    async fn reconcile_removes_orphan_consent_and_keeps_live() {
        let (handler, dao) = make_handler();
        // 两个 client，其一将被删除
        handler
            .store
            .create(make_test_client("reconcile-live"))
            .await
            .unwrap();
        handler
            .store
            .create(make_test_client("reconcile-dead"))
            .await
            .unwrap();
        // 两个 consent 记录（不同 user 避免键覆盖）
        handler
            .grant_consent(0, 8001, "reconcile-live", &["read".into()], &[])
            .await
            .unwrap();
        handler
            .grant_consent(0, 8002, "reconcile-dead", &["read".into()], &[])
            .await
            .unwrap();

        // 删除 dead client 后 reconcile
        handler.store.delete("reconcile-dead").await.unwrap();
        let (removed, kept) = handler.reconcile_consents().await.unwrap();
        assert_eq!(
            removed, 1,
            "应恰好清理 1 条孤儿记录，实际清理 {} 条",
            removed
        );
        assert_eq!(kept, 1, "存活 client 的记录应保留，实际保留 {} 条", kept);

        assert!(
            dao.get("oauth2:consent:0:8002:reconcile-dead")
                .await
                .unwrap()
                .is_none(),
            "已删 client 的 consent 行应被清理"
        );
        assert!(
            dao.get("oauth2:consent:0:8001:reconcile-live")
                .await
                .unwrap()
                .is_some(),
            "存活 client 的 consent 行应保留"
        );

        // 幂等：再次 reconcile 无事可做
        let (removed, _) = handler.reconcile_consents().await.unwrap();
        assert_eq!(removed, 0, "reconcile 必须幂等");
    }

    /// prompt=none：有有效 consent → 直接放行（不弹征询、不弹登录）。
    #[tokio::test]
    async fn prompt_none_with_valid_consent_passes_through() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("prompt-none-001"))
            .await
            .unwrap();
        handler
            .grant_consent(0, 8101, "prompt-none-001", &["read".into()], &[])
            .await
            .unwrap();

        let req = make_request(
            "prompt-none-001",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );
        let resp = handler
            .authorize_with_prompt(&req, Some(8101), AuthorizePrompt::None)
            .await
            .expect("prompt=none + 有效 consent 应放行");
        assert!(
            matches!(resp, AuthorizeResponse::Redirect { .. }),
            "应直接签发授权码"
        );
    }

    /// prompt=none：consent 不足 → interaction_required 错误（RFC 6749 / OIDC
    /// Core §3.1.2.1：不弹交互页，显性错误返回）。
    #[tokio::test]
    async fn prompt_none_without_consent_is_interaction_required() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client_with_scopes(
                "prompt-none-002",
                &["read", "admin"],
            ))
            .await
            .unwrap();
        // 有部分记录但请求扩 scope：同样按 consent 不足处理
        handler
            .grant_consent(0, 8102, "prompt-none-002", &["read".into()], &[])
            .await
            .unwrap();

        let mut req = make_request(
            "prompt-none-002",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );
        req.scope = Some("read admin".into());
        let err = handler
            .authorize_with_prompt(&req, Some(8102), AuthorizePrompt::None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-interaction-required"),
            "consent 不足应 interaction_required，实际: {}",
            err
        );
    }

    /// prompt=none 且未登录：同样 interaction_required（不引导登录）。
    #[tokio::test]
    async fn prompt_none_without_login_is_interaction_required() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("prompt-none-003"))
            .await
            .unwrap();
        let req = make_request(
            "prompt-none-003",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );
        // prompt=none 对应 NoInteraction 变体（AuthorizePrompt::None 为
        // 「未指定 prompt」默认流程：未登录引导登录两段式）
        let err = handler
            .authorize_with_prompt(&req, None, AuthorizePrompt::NoInteraction)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-authorize-interaction-required"),
            "未登录应 interaction_required，实际: {}",
            err
        );
    }

    /// prompt=login：已登录会话仍强制重走登录（force_login 语义），
    /// 恢复票据一次性语义与默认路径一致。
    #[tokio::test]
    async fn prompt_login_forces_reauthentication_roundtrip() {
        let (handler, dao) = make_handler();
        handler
            .store
            .create(make_test_client("prompt-login-001"))
            .await
            .unwrap();
        // 已有有效 consent：默认路径直接放行；prompt=login 必须仍走登录往返
        handler
            .grant_consent(0, 8103, "prompt-login-001", &["read".into()], &[])
            .await
            .unwrap();

        let req = make_request(
            "prompt-login-001",
            &generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        );
        let resp = handler
            .authorize_with_prompt(&req, Some(8103), AuthorizePrompt::Login)
            .await
            .expect("prompt=login 应引导重新登录");
        let login_url = match resp {
            AuthorizeResponse::LoginRequired { login_url } => login_url,
            other => panic!("期望 LoginRequired，实际: {:?}", other),
        };
        let ticket = extract_ticket_from_login_url(&login_url);
        // 旧票据已消费（重新暂存）：恰好一张在库
        let staged = dao.keys("oauth2:authorize-ticket:*").await.unwrap();
        assert_eq!(staged.len(), 1);
        // 登录后续流放行
        let resp = handler.resume(&ticket, Some(8103), &[]).await.unwrap();
        assert!(matches!(resp, AuthorizeResponse::Redirect { .. }));
    }

    /// redirect_uri 自带 query string（白名单精确匹配允许含 `?` 的 URI）时，
    /// code 参数必须用 `&` 追加（RFC 6749 §4.1.2 / RFC 3986），
    /// 恒拼 `?` 会产生双 `?` 畸形跳转 URL。
    #[tokio::test]
    async fn authorize_redirect_url_appends_code_with_ampersand_when_query_exists() {
        let (handler, _) = make_handler();
        let client = OAuth2Client::new(
            "auth-encode-003",
            "secret-123",
            vec!["https://app.example.com/cb?existing=param".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap();
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = AuthorizeRequest {
            response_type: "code".into(),
            client_id: "auth-encode-003".into(),
            redirect_uri: "https://app.example.com/cb?existing=param".into(),
            scope: Some("read".into()),
            state: Some("xyz".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };

        let resp = handler.authorize(&req, Some(1001)).await.expect("授权");
        match resp {
            AuthorizeResponse::Redirect { location } => {
                assert!(location.starts_with("https://app.example.com/cb?existing=param&code="));
                assert!(
                    !location.contains("?code="),
                    "不得出现双 ? 畸形 URL: {}",
                    location
                );
                assert!(location.ends_with("&state=xyz"));
            },
            _ => panic!("期望 Redirect"),
        }
    }

    /// redirect URL 中的 state 参数必须百分号编码。
    #[tokio::test]
    async fn authorize_redirect_url_encodes_state() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-encode-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = AuthorizeRequest {
            response_type: "code".into(),
            client_id: "auth-encode-002".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("state&with=special#chars".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };

        let resp = handler.authorize(&req, Some(1001)).await.expect("授权");
        match resp {
            AuthorizeResponse::Redirect { location } => {
                // state 中的特殊字符必须被编码，不能直接出现
                assert!(
                    !location.contains("state&with=special#chars"),
                    "state 中的特殊字符未被编码: {}",
                    location
                );
                // 应包含编码后的 state
                assert!(location.contains("state="), "应有 state 参数: {}", location);
            },
            _ => panic!("期望 Redirect"),
        }
    }

    /// authorize 端点请求超出 allowed_scopes 的 scope 返回 invalid_scope。
    /// make_test_client 的 allowed_scopes = ["read"]，请求 "admin" 应被拒绝。
    #[tokio::test]
    async fn authorize_scope_not_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-scope-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-scope-001", &challenge);
        req.scope = Some("admin".into());

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-client-invalid-scope"),
            "期望 invalid_scope 错误，实际: {}",
            err
        );
    }

    /// authorize 端点请求合法 scope 正常通过。
    #[tokio::test]
    async fn authorize_scope_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-scope-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-scope-002", &challenge);
        req.scope = Some("read".into());

        let resp = handler.authorize(&req, Some(1)).await.unwrap();
        assert!(matches!(resp, AuthorizeResponse::Redirect { .. }));
    }

    // === consume_code 测试 ===

    #[tokio::test]
    async fn consume_code_returns_auth_data() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("consume-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("consume-001", &challenge);
        let resp = handler.authorize(&req, Some(2001)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let auth_code = handler.consume_code(code).await.unwrap().expect("应存在");
        assert_eq!(auth_code.client_id, "consume-001");
        assert_eq!(auth_code.user_id, 2001);
        assert_eq!(auth_code.code_challenge, challenge);
    }

    #[tokio::test]
    async fn consume_code_one_time_use() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("consume-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("consume-002", &challenge);
        let resp = handler.authorize(&req, Some(2002)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // 第一次消费：成功
        assert!(handler.consume_code(code).await.unwrap().is_some());
        // 第二次消费：已删除
        assert!(handler.consume_code(code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consume_code_nonexistent_returns_none() {
        let (handler, _) = make_handler();
        let result = handler.consume_code("nonexistent-code").await.unwrap();
        assert!(result.is_none());
    }

    /// 并发原子消费 — 16 个 tokio 任务同时用同一 code 调用 consume_code，
    /// 仅一个成功（取到 Some），其余全部返回 None，杜绝并发双花 / 重放。
    #[tokio::test]
    async fn consume_code_atomic_concurrent_only_one_wins() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("consume-conc-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("consume-conc-001", &challenge);
        let resp = handler.authorize(&req, Some(3001)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();

        let handler = std::sync::Arc::new(handler);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let h = handler.clone();
            let c = code.clone();
            handles.push(tokio::spawn(async move {
                h.consume_code(&c).await.unwrap().is_some()
            }));
        }
        let mut wins = 0usize;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(
            wins, 1,
            "并发双花：仅一个 consume_code 应成功，实际 {}",
            wins
        );
    }

    /// 重放检测 + 吊销 — 授权码被消费后记录签发的 token，
    /// 再次消费（重放）时 `revoke_replayed_code_tokens` 应定位并删除签发记录。
    #[tokio::test]
    async fn revoke_replayed_code_tokens_deletes_records() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("revoke-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("revoke-001", &challenge);
        let resp = handler.authorize(&req, Some(3002)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();

        // 首次消费成功
        assert!(handler.consume_code(&code).await.unwrap().is_some());
        // 记录该 code 签发的 token（模拟 issue_tokens 之后）
        handler
            .record_code_tokens(&code, "at-fake-001", Some("rt-fake-001"))
            .await
            .unwrap();
        // 重放：第二次消费返回 None
        assert!(handler.consume_code(&code).await.unwrap().is_none());

        // 吊销此前签发的 token
        let revoked = handler.revoke_replayed_code_tokens(&code).await.unwrap();
        assert!(revoked, "应检测到 codeused 记录并吊销 token");
        // access/refresh token DAO 记录应被删除
        let at_key = crate::constants::DaoKeyPrefix::OAuth2AccessToken.build_key("at-fake-001");
        assert!(
            handler.dao.get(&at_key).await.unwrap().is_none(),
            "access token 记录应已被吊销删除"
        );
        // DAO fallback 存储键（本模块 oauth2_refresh_token_key），断言 refresh token 已被吊销删除
        let rt_key = oauth2_refresh_token_key("rt-fake-001");
        assert!(
            handler.dao.get(&rt_key).await.unwrap().is_none(),
            "refresh token 记录应已被吊销删除"
        );

        // codeused 记录本身应已删除（get_and_delete 语义）
        let revoked_again = handler.revoke_replayed_code_tokens(&code).await.unwrap();
        assert!(!revoked_again, "codeused 记录应已消费删除");
    }

    #[test]
    fn generate_authorization_code_produces_unique() {
        let code1 = generate_authorization_code();
        let code2 = generate_authorization_code();
        assert_ne!(code1, code2);
        assert!(code1.len() >= 43); // 32 bytes → 43 base64url chars
    }
}
