// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `QrLoginService` 实现模块。
//!
//! mod.rs 接口隔离：impl 块不允许留在 mod.rs。
//! 包含 HMAC-SHA256 qr_ticket 签名工具与 `QrLoginService` 方法实现
//!（create/scan/confirm/poll），票据格式与 `protocol/sso` 相同
//!（`{64_hex}.{hmac_b64}`）但实现独立（不 import sso 符号）。

use super::{
    CreatedQrLogin, QrLoginAction, QrLoginConfig, QrLoginPollOutcome, QrLoginScanView,
    QrLoginService, QrLoginSessionData, QrLoginStatus, QrLoginWebContext,
};
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use base64::engine::general_purpose::URL_SAFE as BASE64_URL_SAFE;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

/// HMAC-SHA256 类型别名（qr_ticket 签名）。
type HmacSha256 = Hmac<Sha256>;

/// 本地常量时间字节串比较（bind_token 绑定比对用；避免引入 secure feature 依赖）。
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 会话存储 key 前缀。
const SESSION_KEY_PREFIX: &str = "garrison:qrlogin:session:";
/// confirm_token 存储 key 前缀。
const CONFIRM_KEY_PREFIX: &str = "garrison:qrlogin:confirm:";
/// bind_token（poll 第二票）存储 key 前缀。
const BIND_KEY_PREFIX: &str = "garrison:qrlogin:bind:";

/// 会话存储 key。
fn session_key(qr_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{qr_id}")
}

/// confirm_token 存储 key。
fn confirm_key(token: &str) -> String {
    format!("{CONFIRM_KEY_PREFIX}{token}")
}

impl Default for QrLoginConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: 120,
            confirm_ttl_secs: 60,
            allowed_domains: None,
        }
    }
}

/// 手动 `Debug`：secret 与 HMAC 密钥均不进 Debug 输出（防日志泄露，CWE-532）。
impl std::fmt::Debug for QrLoginService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrLoginService")
            .field("dao", &"<dyn GarrisonDao>")
            .field("secret", &"[REDACTED]")
            .field("config", &self.config)
            .finish()
    }
}

/// 从 UA 解析待登录端设备标签（不下发完整 UA）。
///
/// 判定顺序 Edge → Firefox → Chrome → Safari：Edge UA 同时含 Chrome/Safari
/// 关键字，Chrome UA 含 Safari，必须先判特例。
fn device_label(user_agent: Option<&str>) -> String {
    let Some(ua) = user_agent else {
        return "Unknown device".to_string();
    };
    if ua.contains("Edg") {
        "Edge".to_string()
    } else if ua.contains("Firefox") {
        "Firefox".to_string()
    } else if ua.contains("Chrome") {
        "Chrome".to_string()
    } else if ua.contains("Safari") {
        "Safari".to_string()
    } else {
        "Unknown device".to_string()
    }
}

/// 从 qr_content 提取 host（`://` 之后到 `/`、`?` 或串尾）。
fn extract_host(qr_content: &str) -> Option<String> {
    let rest = qr_content.split_once("://")?.1;
    let host_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// 从 qr_content 提取 t 参数（票据；取到 `&` 或串尾）。
fn extract_ticket(qr_content: &str) -> Option<&str> {
    let idx = qr_content.find("t=")?;
    let value = &qr_content[idx + 2..];
    let value = value.split('&').next().unwrap_or(value);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

impl QrLoginService {
    /// 创建 `QrLoginService` 实例（默认配置：session 120s / confirm 60s / 无域名白名单）。
    ///
    /// # 参数
    /// - `dao`: 数据访问抽象（票据与会话状态存储）。
    /// - `secret`: HMAC 签名密钥（qr_ticket 防伪造，至少 32 字节，对齐 JWT HS256 下限）。
    ///
    /// # 错误
    /// - `secret` 为空时返回 `GarrisonError::InvalidParam`（qrlogin-secret-empty）。
    /// - `secret` 短于 32 字节时返回 `GarrisonError::InvalidParam`（qrlogin-secret-too-short）。
    pub fn new(dao: Arc<dyn GarrisonDao>, secret: impl Into<String>) -> GarrisonResult<Self> {
        let secret: String = secret.into();
        if secret.is_empty() {
            return Err(GarrisonError::InvalidParam(loc!(
                "qrlogin-secret-empty",
                "QR login HMAC secret must not be empty".to_string()
            )));
        }
        if secret.len() < 32 {
            return Err(GarrisonError::InvalidParam(loc!(
                "qrlogin-secret-too-short",
                "QR login HMAC secret must be at least 32 bytes".to_string()
            )));
        }
        Ok(Self {
            dao,
            secret,
            config: QrLoginConfig::default(),
            #[cfg(feature = "listener")]
            listener_manager: None,
        })
    }

    /// 注入配置（构造后不可变）。
    #[must_use]
    pub fn with_config(mut self, config: QrLoginConfig) -> Self {
        self.config = config;
        self
    }

    /// 注入监听器管理器（`listener` feature）：create/scan/confirm/cancel 广播事件。
    #[cfg(feature = "listener")]
    #[must_use]
    pub fn with_listener_manager(
        mut self,
        listener_manager: Arc<crate::listener::GarrisonListenerManager>,
    ) -> Self {
        self.listener_manager = Some(listener_manager);
        self
    }

    // ========================================================================
    // create：签发扫码会话（Web 端）
    // ========================================================================

    /// 创建扫码登录会话（Pending），返回二维码内容与有效期。
    ///
    /// qr_content 携带 HMAC 签名票据；`allowed_domains` 非空时使用白名单首个
    /// 域名拼 URL，否则使用 `garrison://qrlogin` 深链形态（scan 阶段跳过域名校验）。
    pub async fn create_session(&self, web: QrLoginWebContext) -> GarrisonResult<CreatedQrLogin> {
        let qr_id = Self::random_hex64();
        let sig = self.sign_ticket(&qr_id)?;
        let ticket = format!("{qr_id}.{sig}");
        let qr_content = match self.config.allowed_domains.as_ref().and_then(|d| d.first()) {
            Some(domain) => format!("https://{domain}/qrlogin/confirm?t={ticket}"),
            None => format!("garrison://qrlogin?t={ticket}"),
        };
        // 事件上下文在 web move 前采集（create 的 request_context = 待登录端）
        #[cfg(feature = "listener")]
        let request_context = web.ip.clone().map(|ip| crate::listener::RequestContext {
            ip: Some(ip),
            user_agent: web.user_agent.clone(),
        });
        let data = QrLoginSessionData {
            qr_id: qr_id.clone(),
            status: QrLoginStatus::Pending,
            tenant_id: 0,
            app_login_id: None,
            confirm_token_hash: None,
            web,
        };
        let value = serde_json::to_string(&data)
            .map_err(|e| GarrisonError::Internal(format!("qrlogin-session-serialize::{}", e)))?;
        let key = session_key(&qr_id);
        // set_if_absent 原子抢占：256-bit 随机下碰撞概率可忽略，false 视为内部错误
        if !self
            .dao
            .set_if_absent(&key, &value, self.config.session_ttl_secs)
            .await?
        {
            return Err(GarrisonError::Internal(
                "qrlogin-session-id-collision".to_string(),
            ));
        }
        // 双票绑定：bind_token 仅下发给 create 调用方（Web 端本人），poll 出示。
        // 二维码公开可见但不含它——兑换需 qr_id + bind_token 双票。
        let bind_token = Self::random_hex64();
        let bind_key = format!("{BIND_KEY_PREFIX}{bind_token}");
        if !self
            .dao
            .set_if_absent(&bind_key, &qr_id, self.config.session_ttl_secs)
            .await?
        {
            return Err(GarrisonError::Internal(
                "qrlogin-bind-token-collision".to_string(),
            ));
        }
        let created = CreatedQrLogin {
            qr_id,
            bind_token,
            qr_content,
            expires_in_secs: self.config.session_ttl_secs,
        };
        #[cfg(feature = "listener")]
        self.broadcast(crate::listener::GarrisonEvent::QrLoginCreated {
            qr_id: Self::mask_id(&created.qr_id),
            request_context,
        })
        .await;
        Ok(created)
    }

    // ========================================================================
    // scan：App 端扫码（Pending → Scanned，颁发 confirm_token）
    // ========================================================================

    /// App 端扫码：校验 qr_content 域名白名单与票据签名，迁移 Pending → Scanned，
    /// 颁发一次性 confirm_token，返回含**脱敏摘要**的视图（不下发原始 IP/UA）。
    ///
    /// # 错误
    /// - 域名不在白名单：`qrlogin-domain-not-allowed`
    /// - 票据格式/签名无效：`qrlogin-invalid-ticket`
    /// - 会话不存在或已过期：`qrlogin-session-not-found`
    /// - 非 Pending 状态：`qrlogin-already-scanned` / `qrlogin-cancelled`
    pub async fn scan(
        &self,
        qr_content: &str,
        app_login_id: &str,
        app_context: Option<(String, String)>,
    ) -> GarrisonResult<QrLoginScanView> {
        // listener 关闭时上下文无消费者（事件不广播），显式落空避免警告
        #[cfg(not(feature = "listener"))]
        let _ = app_context;
        if let Some(domains) = &self.config.allowed_domains {
            let host_ok = extract_host(qr_content)
                .map(|host| domains.iter().any(|d| d.eq_ignore_ascii_case(&host)))
                .unwrap_or(false);
            if !host_ok {
                return Err(GarrisonError::InvalidParam(loc!(
                    "qrlogin-domain-not-allowed",
                    "QR login ticket domain is not allowed".to_string()
                )));
            }
        }
        let ticket = extract_ticket(qr_content).ok_or_else(Self::invalid_ticket)?;
        let qr_id = self.verify_ticket_signature(ticket)?;

        let (data, remaining_secs) = self
            .load_session_with_ttl(&qr_id)
            .await?
            .ok_or_else(|| Self::session_err("qrlogin-session-not-found"))?;
        match data.status {
            QrLoginStatus::Pending => {},
            QrLoginStatus::Scanned | QrLoginStatus::Confirmed => {
                return Err(Self::session_err("qrlogin-already-scanned"));
            },
            QrLoginStatus::Cancelled => return Err(Self::session_err("qrlogin-cancelled")),
        }

        // 一次性确认凭据：独立随机串，原子抢占写入（256-bit 随机碰撞的
        // false 分支视为内部错误）
        let confirm_token = Self::random_hex64();
        if !self
            .dao
            .set_if_absent(
                &confirm_key(&confirm_token),
                &qr_id,
                self.config.confirm_ttl_secs,
            )
            .await?
        {
            return Err(GarrisonError::Internal(
                "qrlogin-confirm-token-collision".to_string(),
            ));
        }
        let updated = QrLoginSessionData {
            status: QrLoginStatus::Scanned,
            app_login_id: Some(app_login_id.to_string()),
            confirm_token_hash: Some(Self::token_digest(&confirm_token)),
            ..data
        };
        self.write_session(&qr_id, &updated, remaining_secs).await?;

        #[cfg(feature = "listener")]
        self.broadcast(crate::listener::GarrisonEvent::QrLoginScanned {
            qr_id: Self::mask_id(&qr_id),
            app_login_id: app_login_id.to_string(),
            request_context: app_context.map(|(ip, user_agent)| crate::listener::RequestContext {
                ip: Some(ip),
                user_agent: Some(user_agent),
            }),
        })
        .await;

        Ok(QrLoginScanView {
            confirm_token,
            web_device_label: device_label(updated.web.user_agent.as_deref()),
            web_created_at_ms: updated.web.created_at_ms,
            expires_in_secs: self.config.confirm_ttl_secs,
        })
    }

    // ========================================================================
    // confirm：App 端确认/取消（confirm_token 原子消费）
    // ========================================================================

    /// App 端确认或取消：`get_and_delete` 原子消费 confirm_token（重放必失败），
    /// 校验确认者身份与 token 摘要后迁移 Scanned → Confirmed（或任意非终态 → Cancelled）。
    ///
    /// `app_login_id` 必须与 scan 时锁定的确认者一致——「授权动作者」与「身份
    /// 主体」绑定：持有他人 confirm_token 的另一登录用户无法代为确认。不一致
    /// 返回与「token 无效」相同的错误（无区分度，防枚举）。
    ///
    /// 返回迁移后的状态（供 HTTP 层组装响应）。
    ///
    /// # 错误
    /// - token 无效/过期/与会话不匹配/确认者不是扫码者：`qrlogin-confirm-token-invalid`
    /// - 会话已兑换或已过期：`qrlogin-already-consumed`
    /// - 未扫码即确认：`qrlogin-not-scanned`
    /// - 会话已取消：`qrlogin-cancelled`
    pub async fn confirm(
        &self,
        confirm_token: &str,
        app_login_id: &str,
        action: QrLoginAction,
        app_context: Option<(String, String)>,
    ) -> GarrisonResult<QrLoginStatus> {
        #[cfg(not(feature = "listener"))]
        let _ = app_context;
        // 原子消费：并发/重放同一 token 仅首次拿到 Some
        let qr_id = self
            .dao
            .get_and_delete(&confirm_key(confirm_token))
            .await?
            .ok_or_else(|| Self::session_err("qrlogin-confirm-token-invalid"))?;

        let (data, remaining_secs) = self
            .load_session_with_ttl(&qr_id)
            .await?
            .ok_or_else(|| Self::session_err("qrlogin-already-consumed"))?;
        // 摘要比对：token 确实颁发给该会话（防跨会话 token 挪用）
        if data.confirm_token_hash.as_deref() != Some(Self::token_digest(confirm_token).as_str()) {
            return Err(Self::session_err("qrlogin-confirm-token-invalid"));
        }
        // 身份绑定：确认者必须就是扫码者（授权动作者 = 身份主体）
        if data.app_login_id.as_deref() != Some(app_login_id) {
            return Err(Self::session_err("qrlogin-confirm-token-invalid"));
        }

        let new_status = match (action, data.status) {
            (QrLoginAction::Confirm, QrLoginStatus::Scanned) => QrLoginStatus::Confirmed,
            (QrLoginAction::Confirm, QrLoginStatus::Pending) => {
                return Err(Self::session_err("qrlogin-not-scanned"));
            },
            (QrLoginAction::Confirm, QrLoginStatus::Cancelled) => {
                return Err(Self::session_err("qrlogin-cancelled"));
            },
            (QrLoginAction::Confirm, QrLoginStatus::Confirmed) => {
                return Err(Self::session_err("qrlogin-already-consumed"));
            },
            (QrLoginAction::Cancel, QrLoginStatus::Pending | QrLoginStatus::Scanned) => {
                QrLoginStatus::Cancelled
            },
            (QrLoginAction::Cancel, QrLoginStatus::Cancelled) => {
                return Err(Self::session_err("qrlogin-cancelled"));
            },
            (QrLoginAction::Cancel, QrLoginStatus::Confirmed) => {
                return Err(Self::session_err("qrlogin-already-consumed"));
            },
        };
        let updated = QrLoginSessionData {
            status: new_status,
            ..data
        };
        self.write_session(&qr_id, &updated, remaining_secs).await?;

        #[cfg(feature = "listener")]
        {
            let app_login_id = updated.app_login_id.clone().unwrap_or_default();
            let request_context =
                app_context.map(|(ip, user_agent)| crate::listener::RequestContext {
                    ip: Some(ip),
                    user_agent: Some(user_agent),
                });
            let event = if action == QrLoginAction::Confirm {
                crate::listener::GarrisonEvent::QrLoginConfirmed {
                    qr_id: Self::mask_id(&qr_id),
                    app_login_id,
                    request_context,
                }
            } else {
                crate::listener::GarrisonEvent::QrLoginCancelled {
                    qr_id: Self::mask_id(&qr_id),
                    app_login_id,
                    request_context,
                }
            };
            self.broadcast(event).await;
        }
        Ok(new_status)
    }

    // ========================================================================
    // poll：Web 端轮询（Confirmed 分支原子兑换）
    // ========================================================================

    /// Web 端轮询扫码状态（双票：qr_id + bind_token）。
    ///
    /// `bind_token` 是 create 时仅下发给 Web 端本人的第二票：qr_id 编码在公开
    /// 展示的二维码票据中，仅凭 qr_id 可被肩窥/截图者抢先兑换。bind_token 在
    /// 非终态轮询中只校验不消费（Web 端可循环轮询），仅在 Confirmed 兑换分支
    /// `get_and_delete` 原子消费——兑换成功的同一次调用消费第二票，并发/重放
    /// 的输家一律见 `Expired`（不向匿名调用方泄露区分度）。
    pub async fn poll(&self, qr_id: &str, bind_token: &str) -> GarrisonResult<QrLoginPollOutcome> {
        let Some((data, _)) = self.load_session_with_ttl(qr_id).await? else {
            return Ok(QrLoginPollOutcome::Expired);
        };

        // 第二票校验：与 create 时绑定的 qr_id 常量时间比对
        let bind_ok = |consumed: bool| async move {
            let bound = if consumed {
                self.dao
                    .get_and_delete(&format!("{BIND_KEY_PREFIX}{bind_token}"))
                    .await?
            } else {
                self.dao
                    .get(&format!("{BIND_KEY_PREFIX}{bind_token}"))
                    .await?
            };
            Ok::<_, crate::error::GarrisonError>(matches!(bound,
                    Some(b) if ct_eq_bytes(b.as_bytes(), qr_id.as_bytes())))
        };

        match data.status {
            QrLoginStatus::Pending => {
                if bind_ok(false).await? {
                    Ok(QrLoginPollOutcome::Pending)
                } else {
                    Ok(QrLoginPollOutcome::Expired)
                }
            },
            QrLoginStatus::Scanned => {
                if bind_ok(false).await? {
                    Ok(QrLoginPollOutcome::Scanned)
                } else {
                    Ok(QrLoginPollOutcome::Expired)
                }
            },
            QrLoginStatus::Cancelled => {
                if bind_ok(false).await? {
                    Ok(QrLoginPollOutcome::Cancelled)
                } else {
                    Ok(QrLoginPollOutcome::Expired)
                }
            },
            QrLoginStatus::Confirmed => {
                // 原子消费第二票：并发/重放仅一者通过，再原子兑换会话
                if !bind_ok(true).await? {
                    return Ok(QrLoginPollOutcome::Expired);
                }
                // 原子兑换：并发 poll 同一 Confirmed 会话仅一者成功
                match self.dao.get_and_delete(&session_key(qr_id)).await {
                    Ok(Some(_)) => Ok(QrLoginPollOutcome::Confirmed {
                        login_id: data.app_login_id.unwrap_or_default(),
                        tenant_id: data.tenant_id,
                    }),
                    Ok(None) => Ok(QrLoginPollOutcome::Expired),
                    // DAO 瞬时故障：补偿回写 bind_token（复查修复）——否则合法
                    // Web 端两票均已损失，只能重开整个扫码流程
                    Err(e) => {
                        let _ = self
                            .dao
                            .set(
                                &format!("{BIND_KEY_PREFIX}{bind_token}"),
                                qr_id,
                                self.config.session_ttl_secs,
                            )
                            .await;
                        Err(e)
                    },
                }
            },
        }
    }

    // ========================================================================
    // 内部工具
    // ========================================================================

    /// 读取会话（返回数据 + 剩余 TTL 秒；TTL 未知时回退配置值）。
    pub(crate) async fn load_session_with_ttl(
        &self,
        qr_id: &str,
    ) -> GarrisonResult<Option<(QrLoginSessionData, u64)>> {
        let Some((json, ttl)) = self.dao.get_with_ttl(&session_key(qr_id)).await? else {
            return Ok(None);
        };
        let data: QrLoginSessionData = serde_json::from_str(&json)
            .map_err(|e| GarrisonError::Internal(format!("qrlogin-session-parse::{}", e)))?;
        let remaining = ttl
            .map(|d| d.as_secs())
            .filter(|s| *s > 0)
            .unwrap_or(self.config.session_ttl_secs);
        Ok(Some((data, remaining)))
    }

    /// 读取会话（不关心剩余 TTL 的场景）。
    #[cfg(test)]
    pub(crate) async fn load_session(
        &self,
        qr_id: &str,
    ) -> GarrisonResult<Option<QrLoginSessionData>> {
        Ok(self.load_session_with_ttl(qr_id).await?.map(|(d, _)| d))
    }

    /// 测试辅助：为 Pending 会话直接注入 confirm_token（真实流程中 token 仅在
    /// scan 时颁发，此入口用于钉住 confirm 的未扫码守卫分支）。
    #[cfg(test)]
    pub(crate) async fn store_confirm_token_for_test(&self, token: &str, qr_id: &str) {
        self.dao
            .set(&confirm_key(token), qr_id, self.config.confirm_ttl_secs)
            .await
            .expect("test confirm token set should succeed");
        if let Some((mut data, remaining)) = self.load_session_with_ttl(qr_id).await.unwrap() {
            data.confirm_token_hash = Some(Self::token_digest(token));
            // 模拟 scan 的完整副作用：确认者身份已锁定（否则身份绑定守卫先于
            // not-scanned 守卫命中，测不到目标分支）
            data.app_login_id = Some("user-1".to_string());
            self.write_session(qr_id, &data, remaining)
                .await
                .expect("test session write-back should succeed");
        }
    }

    /// 写回会话（保留剩余 TTL）。
    async fn write_session(
        &self,
        qr_id: &str,
        data: &QrLoginSessionData,
        remaining_secs: u64,
    ) -> GarrisonResult<()> {
        let value = serde_json::to_string(data)
            .map_err(|e| GarrisonError::Internal(format!("qrlogin-session-serialize::{}", e)))?;
        self.dao
            .set(&session_key(qr_id), &value, remaining_secs)
            .await
    }

    /// 计算 `qr_id` 的 HMAC-SHA256 签名（URL-safe base64）。
    pub(super) fn sign_ticket(&self, random_part: &str) -> GarrisonResult<String> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|e| GarrisonError::Internal(format!("qrlogin-ticket-hmac-init::{}", e)))?;
        mac.update(random_part.as_bytes());
        Ok(BASE64_URL_SAFE.encode(mac.finalize().into_bytes()))
    }

    /// 验证 qr_ticket 的 HMAC 签名，通过则返回 qr_id。
    ///
    /// 签名解码与验证失败统一返回同一错误，不泄露失败原因（防侧信道）。
    pub(super) fn verify_ticket_signature(&self, ticket: &str) -> GarrisonResult<String> {
        let (random_part, sig_b64) = ticket.split_once('.').ok_or_else(Self::invalid_ticket)?;
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|e| GarrisonError::Internal(format!("qrlogin-ticket-hmac-init::{}", e)))?;
        mac.update(random_part.as_bytes());
        let sig_bytes = BASE64_URL_SAFE
            .decode(sig_b64)
            .map_err(|_| Self::invalid_ticket())?;
        mac.verify_slice(&sig_bytes)
            .map_err(|_| Self::invalid_ticket())?;
        Ok(random_part.to_string())
    }

    /// 生成 64-hex 随机串（`Uuid::new_v4().simple()` ×2，与 sso issue_ticket 同源）。
    pub(super) fn random_hex64() -> String {
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
    }

    /// 事件载荷 ID 掩码（前 8 字符 + `***`，对齐 listener 的 token 掩码规约）。
    /// 仅 listener 广播路径使用（feature 关闭时一并剔除）。
    #[cfg(feature = "listener")]
    pub(super) fn mask_id(id: &str) -> String {
        let mut out: String = id.chars().take(8).collect();
        out.push_str("***");
        out
    }

    /// 广播扫码登录事件（listener 未注入时 no-op；feature 关闭时整体编译剔除）。
    #[cfg(feature = "listener")]
    async fn broadcast(&self, event: crate::listener::GarrisonEvent) {
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&event).await;
        }
    }

    /// confirm_token 的 SHA-256 hex 摘要（会话内只存摘要，不落明文）。
    pub(super) fn token_digest(token: &str) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// 统一的无效票据错误。
    fn invalid_ticket() -> GarrisonError {
        GarrisonError::InvalidParam(loc!(
            "qrlogin-invalid-ticket",
            "QR login ticket signature is invalid".to_string()
        ))
    }

    /// 统一的会话状态类错误（InvalidToken 族，HTTP 层映射 400）。
    fn session_err(key: &'static str) -> GarrisonError {
        GarrisonError::InvalidToken(loc!(
            key,
            format!(
                "QR login session state error: {}",
                key.replace("qrlogin-", "")
            )
            .to_string()
        ))
    }
}
