// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! JWT RefreshToken Rotation 模块。
//!
//! 基于 hash chain 的 RefreshToken 轮换：每次 `rotate` 时，新 token 的
//! `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
//! 旧 token 标记为 `revoked`，防止重放攻击。
//!
//! ## 核心抽象
//!
//! - [`RefreshTokenRecord`](crate::protocol::jwt::refresh::RefreshTokenRecord)：`refresh_tokens` 表行结构（hash chain 字段）
//! - `RefreshTokenRotation`：rotate 服务
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE refresh_tokens (
//! token_hash TEXT PRIMARY KEY,
//! parent_token_hash TEXT,
//! login_id TEXT NOT NULL,
//! tenant_id INTEGER NOT NULL DEFAULT 0,
//! key_version INTEGER NOT NULL,
//! expires_at INTEGER NOT NULL,
//! revoked INTEGER NOT NULL DEFAULT 0,
//! created_at INTEGER NOT NULL
//! );
//! ```

// ============================================================================
// RefreshTokenRecord 定义
// ============================================================================

/// `refresh_tokens` 表行结构。
///
/// 基于 hash chain 的 RefreshToken 记录：每次 `rotate` 时，新 token 的
/// `parent_token_hash` 指向旧 token 的 `token_hash`，形成链式结构。
/// 旧 token 标记为 `revoked`，防止重放攻击。
///
/// # 字段
///
/// ## Hash chain 字段（JWT 模块使用）
///
/// - `token_hash`: 当前 token 的 SHA-256 哈希（主键）
/// - `parent_token_hash`: 旧 token 的哈希（首次签发为 `None`）
/// - `login_id`: 关联用户 ID（JWT 模块使用）
/// - `tenant_id`: 租户 ID（多租户隔离）
/// - `key_version`: 密钥轮换版本号（支持密钥轮换时区分）
/// - `expires_at`: 过期时间（Unix 秒）
/// - `revoked`: 是否已撤销（rotate 后旧 token 标记为 true）
/// - `created_at`: 创建时间（Unix 秒）
///
/// ## OAuth2 扩展字段（JWT 模块生成的记录为 `None`）
///
/// - `client_id`: OAuth2 客户端 ID（JWT 模块不使用，设为 `None`）
/// - `scopes`: OAuth2 授权的 scope 列表（空格分隔，JWT 模块不使用）
/// - `username`: OAuth2 password grant type 用户名（JWT 模块不使用）
/// - `user_id`: OAuth2 user_id（与 `login_id` 区分：`login_id` 是 JWT 模块的 i64 ID，
///   `user_id` 是 OAuth2 的 `Option<i64>`，`client_credentials` 时为 `None`）
///
/// 反序列化时这 4 个字段必须**显式存在**（值可为 `null`），缺失任一字段即失败
/// （fail-closed，见 `deserialize_required_option`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenRecord {
    /// 当前 token 的 SHA-256 哈希（主键）。
    pub token_hash: String,
    /// 旧 token 的哈希（首次签发为 `None`）。
    pub parent_token_hash: Option<String>,
    /// 关联用户 ID（JWT 模块使用）。
    pub login_id: i64,
    /// 租户 ID（多租户隔离）。
    pub tenant_id: i64,
    /// 密钥轮换版本号。
    pub key_version: u32,
    /// 过期时间（Unix 秒）。
    pub expires_at: i64,
    /// 是否已撤销（rotate 后旧 token 标记为 true）。
    pub revoked: bool,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
    /// 被轮换消费的时刻（Unix 秒；首次签发或轮换产生的新记录为 `None`）。
    ///
    /// 原子消费（revoked 0→1）时写入；重用分级与宽限窗口据此判定提交的
    /// 旧 token 是否处于宽限窗口内。字段缺失（JSON 无该 key）视为 `None`。
    #[serde(default)]
    pub rotated_at: Option<i64>,

    /// OAuth2 客户端 ID（JWT 模块不使用）。
    #[serde(deserialize_with = "deserialize_required_option")]
    pub client_id: Option<String>,
    /// OAuth2 授权的 scope 列表（空格分隔）。
    #[serde(deserialize_with = "deserialize_required_option")]
    pub scopes: Option<String>,
    /// OAuth2 password grant type 用户名。
    #[serde(deserialize_with = "deserialize_required_option")]
    pub username: Option<String>,
    /// OAuth2 user_id（与 `login_id` 区分）。
    #[serde(deserialize_with = "deserialize_required_option")]
    pub user_id: Option<i64>,
}

/// serde `deserialize_with` 辅助：`Option<T>` 字段显式必填（key 缺失即反序列化失败）。
///
/// serde 默认把 `Option<T>` 字段的 key 缺失解释为 `None`；本辅助使字段缺失时返回
/// `missing field` 错误，key 显式存在时 `null` → `None`、有值 → `Some`（fail-closed）。
fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize as _;
    Option::<T>::deserialize(deserializer)
}

// ============================================================================
// 重用三级分类
// ============================================================================

/// Refresh token 重用三级分类。
///
/// 提交的 refresh token 已被消费（revoked=1）时，`detect_reuse` 沿 hash chain
/// 子代方向回溯分级：
///
/// - [`RecentPrev`](Self::RecentPrev)：提交 hash 是存活链头的直接父代
///   （回溯 1 跳）——并发双发/网络重试的典型形态
/// - [`OrphanedBranch`](Self::OrphanedBranch)：回溯 >1 跳才命中存活链头
///   （更早祖先复现）
/// - [`StaleLineage`](Self::StaleLineage)：无存活血缘（无任何子代，或后代
///   已全部吊销）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTokenReuseSubtype {
    /// 命中存活链头记录的 `parent_token_hash`（回溯 1 跳）。
    RecentPrev,
    /// 命中更早祖先（回溯 >1 跳）。
    OrphanedBranch,
    /// 无血缘关系（无子代或后代全部已吊销）。
    StaleLineage,
}

// ============================================================================
// RefreshTokenRotation 服务（sqlite gated）
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod service {
    use super::{RefreshTokenRecord, RefreshTokenReuseSubtype};
    use crate::config::RecentReuseBehaviour;
    use crate::error::{GarrisonError, GarrisonResult};
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
    use dbnexus::DbPool;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;
    use uuid::Uuid;

    /// 重用分级沿子代链回溯的深度上限。
    ///
    /// 回溯是按 `parent_token_hash` 逐跳反查的 BFS；上限封顶单次检测的查询量。
    /// 达到上限仍存在子代链时按 `OrphanedBranch` 处置（血缘存在但链头过深）。
    const REUSE_LINEAGE_MAX_DEPTH: usize = 32;

    /// 宽限兑现的竞态等待轮询间隔。
    const GRACE_RACE_POLL: Duration = Duration::from_millis(10);

    /// 宽限兑现的竞态等待上限。
    ///
    /// 仅用于「轮换在途」候选路径（对方已原子消费、子代尚未落库）：轮询进程内
    /// 凭据表直至胜者登记或超时；超过即放弃等待、按重用处置分派。
    const GRACE_RACE_DEADLINE: Duration = Duration::from_millis(250);

    /// 宽限兑现凭据（进程内暂存，不落库）。
    ///
    /// `new_refresh` 是轮换时签发给胜者的原始 refresh token 材料——兑现方拿到
    /// 与胜者完全相同的 token（不重旋转）；`uses` 记录已兑现次数，上限为
    /// `grace_max_uses`（胜者自身的正常消费不计入预算）。保留上界：条目驻留至
    /// 窗口过期（后续登记时 `retain` 惰性清理）或链吊销（`revoke_chain` 同步
    /// 移除），静默期（无新轮换、无吊销）不后台回收——上界为「最后一个窗口内
    /// 活跃 old_hash 一条」，单条仅 token 材料 + login_id，无放大风险。
    struct GraceEntry {
        new_refresh: String,
        login_id: String,
        rotated_at: i64,
        uses: u32,
    }

    /// RefreshToken Rotation 服务（hash chain + rotate + reuse detection）。
    ///
    /// 完整实现在 逐步构建：
    /// - -`rotate` 基础实现（SHA-256 hash + INSERT new + UPDATE old revoked=1）
    /// - -`detect_reuse` 查表 revoked=1
    /// - -`revoke_chain` 递归 UPDATE parent_token_hash 链
    /// - -`rotate` 追加 reuse detection（重用则 revoke_chain 后返回 InvalidToken）
    ///
    /// # 字段
    ///
    /// - `pool`: SQLite 连接池（查 `refresh_tokens` 表）
    /// - `jwt_handler`: JWT 处理器（签发新 access token）
    /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
    ///
    /// # 冲突暴露
    ///
    /// 原描述 `pub dao: Arc<dyn GarrisonDao>` 不够——
    /// `rotate` 需查 SQL（DbPool）+ 签发 access token（JwtHandler）+ 读 key_version。
    /// 决策：struct 持有 `pool: DbPool` + `jwt_handler: Arc<JwtHandler>` + `key_version: Arc<RwLock<u32>>`，
    /// 不持有 `dao`（GarrisonDao 是缓存层抽象，不支持 SQL 查询）。
    pub struct RefreshTokenRotation {
        /// SQLite 连接池（查 `refresh_tokens` 表）。
        pub pool: DbPool,
        /// JWT 处理器（签发新 access token）。
        pub jwt_handler: Arc<JwtHandler>,
        /// 密钥轮换版本号（写入新 record 的 key_version 字段）。
        pub key_version: Arc<RwLock<u32>>,
        /// 重用处置策略（RecentPrev / OrphanedBranch 两级；StaleLineage 恒盗用）。
        pub reuse_behaviour: RecentReuseBehaviour,
        /// 宽限窗口时长秒数（<= 0 = 关闭）。
        pub grace_period_secs: i64,
        /// 宽限窗口内同一旧 token 的最大宽限兑现次数。
        pub grace_max_uses: u32,
        /// 宽限兑现凭据表（old_hash → 凭据），进程内暂存。
        grace_entries: Arc<Mutex<HashMap<String, GraceEntry>>>,
    }

    impl RefreshTokenRotation {
        /// 创建 RefreshTokenRotation 实例。
        ///
        /// # 参数
        /// - `pool`: SQLite 连接池（用于查 `refresh_tokens` 表）
        /// - `jwt_handler`: JWT 处理器（签发新 access token）
        /// - `key_version`: 密钥轮换版本号（写入新 record 的 key_version 字段）
        pub fn new(
            pool: DbPool,
            jwt_handler: Arc<JwtHandler>,
            key_version: Arc<RwLock<u32>>,
        ) -> Self {
            Self {
                pool,
                jwt_handler,
                key_version,
                reuse_behaviour: RecentReuseBehaviour::default(),
                grace_period_secs: 0,
                grace_max_uses: 1,
                grace_entries: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        /// 设置重用处置策略（默认 `TheftDetected`）。
        ///
        /// 生产装配时应取自 `GarrisonConfig::recent_reuse_behaviour`。
        pub fn with_reuse_behaviour(mut self, behaviour: RecentReuseBehaviour) -> Self {
            self.reuse_behaviour = behaviour;
            self
        }

        /// 设置宽限窗口（默认 0 = 关闭）。
        ///
        /// `period_secs <= 0` 关闭窗口；`max_uses` 为窗口内同一旧 token 的最大
        /// 宽限兑现次数。生产装配时应取自 `GarrisonConfig` 的
        /// `refresh_grace_period_secs` / `refresh_grace_max_uses`。
        pub fn with_grace_window(mut self, period_secs: i64, max_uses: u32) -> Self {
            self.grace_period_secs = period_secs;
            self.grace_max_uses = max_uses;
            self
        }

        /// 计算 SHA-256 并返回 hex 字符串。
        fn sha256_hex(s: &str) -> String {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let result = hasher.finalize();
            result.iter().map(|b| format!("{:02x}", b)).collect()
        }

        /// 获取当前 Unix 时间戳（秒）。
        fn now_unix() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }

        /// rotate 旧 refresh token 为新 access + 新 refresh。
        ///
        /// 流程：
        /// 1. 计算 `old_hash = SHA-256(old_token)`
        /// 2. 预检 reuse 并三级分类（`detect_reuse`），命中则按序尝试：宽限
        ///    窗口兑现（窗口开启 + `rotated_at` 在窗口内 + 子类型具备兑现
        ///    资格）——返回胜者签发的既有新 refresh（不重旋转）+ 新签
        ///    access；未兑现则处置分派（`dispose_reuse`）——StaleLineage 恒
        ///    吊销整链 + `TokenRevoked`；RecentPrev / OrphanedBranch 按
        ///    `reuse_behaviour` 分派（TheftDetected 吊销 + `TokenRevoked` /
        ///    Unauthorised 仅 `InvalidToken` 不吊销链）
        /// 3. **原子消费**：条件 UPDATE（`revoked = 0 → 1`，同语句写 `rotated_at`）
        ///    作为 compare-and-swap，并发对同一 old_token 的 rotate 仅有一个
        ///    调用方 `rows_affected = 1`；未抢到的调用方在宽限窗口开启且该
        ///    token 恰被轮换时兑现胜者的既有新 token（在途竞态容忍），否则
        ///    直接返回 `InvalidToken`（不吊销链——并发落败方与胜者是同一
        ///    客户端的同时请求/网络重试，误吊销会击落胜者的新 session）。
        ///    据此消除 SELECT/UPDATE 分离的 TOCTOU 双花窗口：并发同 token
        ///    刷新只能一个胜者
        /// 4. SELECT 读取 login_id / tenant_id 及 OAuth2 扩展字段（此时已独占持有
        ///    消费权，无需再过滤 `revoked = 0`）
        /// 5. 生成新 refresh token（UUID v4）+ 签发新 access token（JwtHandler，1 小时有效期）
        /// 6. 计算 `new_hash = SHA-256(new_refresh)`，INSERT new record
        ///    （`parent_token_hash = old_hash`, `revoked=0`，7 天过期，继承
        ///    OAuth2 扩展字段）；宽限窗口开启时登记兑现凭据
        /// 7. 返回 `(new_access, new_refresh)`
        ///
        /// 崩溃/失败语义（fail-closed）：若在原子消费后、INSERT 前进程崩溃，旧
        /// token 已吊销而无新 token——用户需重新登录，绝不出现新旧 token 同时
        /// 有效。INSERT 因故障失败（非崩溃）时走补偿：删除半成品子代行并把旧
        /// token 回退到未消费态，原链仍可用（见 `compensate_failed_rotation`）。
        ///
        /// # 错误
        /// - `GarrisonError::TokenRevoked`: old_token 已被消费（reuse 且处置为盗用）
        /// - `GarrisonError::InvalidToken`: old_token 不存在 / 重用处置为 Unauthorised /
        ///   并发落败且未命中宽限兑现
        /// - `GarrisonError::Dao`: SQL 查询/INSERT/UPDATE 失败（INSERT 失败含
        ///   补偿结果标注：`rolled-back` / `insert-and-compensate-failed`）
        /// - `GarrisonError::Internal`: JwtHandler 签发失败（由 sign 透传）
        pub async fn rotate(&self, old_token: &str) -> GarrisonResult<(String, String)> {
            let old_hash = Self::sha256_hex(old_token);

            // reuse 预检——三级分类后按处置策略分派：
            // - 宽限窗口命中（含轮换在途竞态等待）：返回胜者签发的既有新 token
            // - StaleLineage（无存活血缘）：恒按盗用吊销整条链，不受配置影响
            // - RecentPrev / OrphanedBranch：按 `reuse_behaviour` 分派
            if let Some(subtype) = self.detect_reuse(&old_hash).await? {
                if let Some((new_refresh, login_id)) =
                    self.try_grace_redemption(&old_hash, subtype).await?
                {
                    let new_access = self.jwt_handler.sign(&login_id, 3600)?;
                    return Ok((new_access, new_refresh));
                }
                return Err(self.dispose_reuse(&old_hash, subtype).await?);
            }

            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;

            // 原子消费（compare-and-swap）：仅当仍 revoked=0 时置为 revoked=1，
            // 并发竞争同一 old_token 的 rotate 恰有一个调用方 rows_affected=1；
            // rotated_at 同语句写入（消费时刻），供重用分级与宽限窗口判定
            let claim_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE refresh_tokens SET revoked = 1, rotated_at = ? \
                 WHERE token_hash = ? AND revoked = 0",
                vec![
                    Value::BigInt(Some(Self::now_unix())),
                    Value::String(Some(old_hash.clone())),
                ],
            );
            let claimed = conn
                .execute_raw(claim_stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-claim::{}", e)))?;
            if claimed.rows_affected() == 0 {
                // 未抢到消费权：token 不存在，或已被并发 rotate 消费。
                // 宽限窗口开启且该 token 恰被轮换（rotated_at 在窗口内）时，
                // 并发落败方短暂等待胜者登记凭据并兑现同一新 token（在途竞态）；
                // 未命中则保持既有语义（InvalidToken，不吊销链——并发落败方与
                // 胜者是同一客户端的同时请求/网络重试，误吊销会击落胜者的新
                // session；真正的「消费后再次呈现」重用由入口处的 detect_reuse
                // 预检识别并处置）。
                let rotated_at_in_window = if self.grace_period_secs > 0 {
                    matches!(
                        Self::fetch_rotated_at(conn, &old_hash).await?,
                        Some(t) if Self::now_unix() - t <= self.grace_period_secs
                    )
                } else {
                    false
                };
                // 立即释放池连接再继续：轮询等待目标纯在进程内存，不得在持有
                // 连接时等待或调用 detect_reuse/revoke_chain（单连接池下会自
                // 等待直至 acquire 超时）。
                drop(session);
                let graced = if rotated_at_in_window {
                    self.await_grace_redemption(&old_hash).await
                } else {
                    None
                };
                if let Some((new_refresh, login_id)) = graced {
                    let new_access = self.jwt_handler.sign(&login_id, 3600)?;
                    return Ok((new_access, new_refresh));
                }
                return Err(GarrisonError::InvalidToken(
                    "jwt-refresh-token-consumed::".to_string(),
                ));
            }

            // 本调用方已独占持有该 token 的消费权，读取会话数据
            // （无需再过滤 revoked=0——上方条件 UPDATE 已将其置 1）
            // 扩展 SELECT 读取 OAuth2 字段以便继承到新记录
            let select_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT login_id, tenant_id, client_id, scopes, username, user_id \
                 FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(old_hash.clone()))],
            );
            let row = conn
                .query_one_raw(select_stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?
                .ok_or_else(|| {
                    GarrisonError::InvalidToken("jwt-refresh-token-consumed::".to_string())
                })?;

            let login_id: String = row
                .try_get("", "login_id")
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
            let tenant_id: i64 = row
                .try_get("", "tenant_id")
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
            // 读取 OAuth2 扩展字段（旧记录可能为 NULL，使用 ok().flatten() 容错）
            let client_id: Option<String> = row.try_get("", "client_id").ok().flatten();
            let scopes: Option<String> = row.try_get("", "scopes").ok().flatten();
            let username: Option<String> = row.try_get("", "username").ok().flatten();
            let user_id: Option<i64> = row.try_get("", "user_id").ok().flatten();

            // 生成新 refresh token + 签发新 access token
            let new_refresh = Uuid::new_v4().to_string();
            let new_access = self.jwt_handler.sign(&login_id, 3600)?;
            let new_hash = Self::sha256_hex(&new_refresh);
            let now = Self::now_unix();
            let kv = *self
                .key_version
                .read()
                .expect("key_version RwLock should not be poisoned");

            // INSERT new record（parent_token_hash = old_hash, revoked=0, 7 天过期）
            // 继承 OAuth2 扩展字段
            // （旧 record 已在原子消费步置 revoked=1，无需再 UPDATE）
            let insert_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO refresh_tokens \
                 (token_hash, parent_token_hash, login_id, tenant_id, key_version, \
                  expires_at, revoked, created_at, client_id, scopes, username, user_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    Value::String(Some(new_hash.clone())),
                    Value::String(Some(old_hash.clone())),
                    Value::String(Some(login_id.clone())),
                    Value::BigInt(Some(tenant_id)),
                    Value::BigInt(Some(kv as i64)),
                    Value::BigInt(Some(now + 86400 * 7)),
                    Value::BigInt(Some(0)),
                    Value::BigInt(Some(now)),
                    client_id
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    scopes
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    username
                        .clone()
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    user_id
                        .map(|i| Value::BigInt(Some(i)))
                        .unwrap_or(Value::BigInt(None)),
                ],
            );
            // 子代落库失败（旋转中途写失败）：补偿删除半成品行并回退本次消费，
            // 原链保持可用；补偿自身失败时链维持已消费态（fail-closed：绝不出现
            // 新旧 token 同时有效的窗口），两类错误均显性上报。
            if let Err(insert_err) = conn.execute_raw(insert_stmt).await {
                return match Self::compensate_failed_rotation(conn, &old_hash).await {
                    Ok(()) => Err(GarrisonError::Dao(format!(
                        "jwt-refresh-insert-rolled-back::{}",
                        insert_err
                    ))),
                    Err(compensate_err) => Err(GarrisonError::Dao(format!(
                        "jwt-refresh-insert-and-compensate-failed::insert={insert_err}::compensate={compensate_err}"
                    ))),
                };
            }

            // 宽限窗口开启时登记兑现凭据（顺带清理窗口外过期条目）
            self.record_grace_entry(&old_hash, &new_refresh, &login_id, now);

            Ok((new_access, new_refresh))
        }

        /// 旋转中途写失败的补偿：删除本次旋转的半成品子代行（防孤儿），并把
        /// 原 token 回退到未消费态（revoked=0、rotated_at=NULL）。
        ///
        /// 删除范围为 `parent_token_hash = old_hash` 的行——原 token 在本次
        /// 原子消费前 revoked=0，该谓词命中的子代只可能来自本次失败的旋转
        /// （或此前崩溃遗留的孤儿），一并清理。
        ///
        /// **已知竞态局限**：restore 无状态谓词，无法区分「回退本次消费」与
        /// 「回退并发到达的外部吊销」——若在消费成功后、补偿执行前，同一链的
        /// 祖先 token 重放触发盗用吊销（`revoke_chain` 覆盖本 token），补偿会
        /// 把该盗用吊销一并回退。窗口需同时满足「INSERT 失败 + 窗口内外部
        /// 吊销」，触发面窄；彻底消除需 claim/INSERT/补偿单事务化或吊销来源
        /// 标记列（超出本条目 schema 范围），权衡记录于此不静默。
        async fn compensate_failed_rotation(
            conn: &DatabaseConnection,
            old_hash: &str,
        ) -> GarrisonResult<()> {
            let delete_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "DELETE FROM refresh_tokens WHERE parent_token_hash = ?",
                vec![Value::String(Some(old_hash.to_string()))],
            );
            conn.execute_raw(delete_stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-compensate-delete::{}", e)))?;
            let restore_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE refresh_tokens SET revoked = 0, rotated_at = NULL \
                 WHERE token_hash = ?",
                vec![Value::String(Some(old_hash.to_string()))],
            );
            conn.execute_raw(restore_stmt).await.map_err(|e| {
                GarrisonError::Dao(format!("jwt-refresh-compensate-restore::{}", e))
            })?;
            Ok(())
        }

        /// 签发初始 refresh_token 并写入 refresh_tokens 表。
        ///
        /// 用于 OAuth2 authorization_code / password grant type 首次签发 refresh_token。
        /// 不存在父 token（`parent_token_hash = None`），`revoked = 0`。
        ///
        /// # 参数
        /// - `client_id`: OAuth2 客户端 ID
        /// - `user_id`: OAuth2 用户 ID（`client_credentials` 时为 `None`）
        /// - `scopes`: 授权的 scope 列表（空列表时存储为 `NULL`）
        /// - `username`: password grant type 用户名（其他 grant type 为 `None`）
        /// - `login_id`: JWT 模块的用户 ID（与 `user_id` 区分，通常相同但语义不同）
        /// - `tenant_id`: 租户 ID（多租户隔离）
        /// - `ttl_seconds`: refresh_token 有效期（秒）
        ///
        /// # 返回
        /// 原始 refresh_token 字符串（调用方需返回给客户端）
        ///
        /// # 错误
        /// - `GarrisonError::Dao`: SQL INSERT 失败
        pub async fn issue(
            &self,
            client_id: &str,
            user_id: Option<i64>,
            scopes: &[String],
            username: Option<&str>,
            login_id: i64,
            tenant_id: i64,
            ttl_seconds: i64,
        ) -> GarrisonResult<String> {
            let refresh_token = Uuid::new_v4().to_string();
            let token_hash = Self::sha256_hex(&refresh_token);
            let now = Self::now_unix();
            let kv = *self
                .key_version
                .read()
                .expect("key_version RwLock should not be poisoned");

            let scopes_str = if scopes.is_empty() {
                None
            } else {
                Some(scopes.join(" "))
            };

            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;

            let insert_stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO refresh_tokens \
                 (token_hash, parent_token_hash, login_id, tenant_id, key_version, \
                  expires_at, revoked, created_at, client_id, scopes, username, user_id) \
                 VALUES (?, NULL, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
                vec![
                    Value::String(Some(token_hash)),
                    Value::BigInt(Some(login_id)),
                    Value::BigInt(Some(tenant_id)),
                    Value::BigInt(Some(kv as i64)),
                    Value::BigInt(Some(now + ttl_seconds)),
                    Value::BigInt(Some(now)),
                    Value::String(Some(client_id.to_string())),
                    scopes_str
                        .map(|s| Value::String(Some(s)))
                        .unwrap_or(Value::String(None)),
                    username
                        .map(|s| Value::String(Some(s.to_string())))
                        .unwrap_or(Value::String(None)),
                    user_id
                        .map(|i| Value::BigInt(Some(i)))
                        .unwrap_or(Value::BigInt(None)),
                ],
            );
            conn.execute_raw(insert_stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-insert::{}", e)))?;

            Ok(refresh_token)
        }

        /// 验证 refresh_token 有效性（不轮换）。
        ///
        /// 用于 OAuth2 introspect 端点或调用方需要只读检查 token 有效性。
        ///
        /// # 参数
        /// - `token`: 原始 refresh_token 字符串（内部计算 SHA-256）
        ///
        /// # 返回
        /// - `Ok(Some(record))`: token 有效且未 revoked
        /// - `Ok(None)`: token 不存在或已 revoked
        /// - `Err(GarrisonError::Dao)`: SQL 查询失败
        pub async fn validate(&self, token: &str) -> GarrisonResult<Option<RefreshTokenRecord>> {
            let token_hash = Self::sha256_hex(token);
            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;

            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT token_hash, parent_token_hash, login_id, tenant_id, \
                        key_version, expires_at, revoked, created_at, rotated_at, \
                        client_id, scopes, username, user_id \
                 FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
                vec![Value::String(Some(token_hash.clone()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;

            match row {
                Some(row) => {
                    let login_id: String = row
                        .try_get("", "login_id")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let tenant_id: i64 = row
                        .try_get("", "tenant_id")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let key_version: i64 = row
                        .try_get("", "key_version")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let expires_at: i64 = row
                        .try_get("", "expires_at")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let revoked: i64 = row
                        .try_get("", "revoked")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let created_at: i64 = row
                        .try_get("", "created_at")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    let rotated_at: Option<i64> = row.try_get("", "rotated_at").ok().flatten();
                    let parent_token_hash: Option<String> =
                        row.try_get("", "parent_token_hash").ok().flatten();
                    let client_id: Option<String> = row.try_get("", "client_id").ok().flatten();
                    let scopes: Option<String> = row.try_get("", "scopes").ok().flatten();
                    let username: Option<String> = row.try_get("", "username").ok().flatten();
                    let user_id: Option<i64> = row.try_get("", "user_id").ok().flatten();

                    // login_id 在 SQL 表中是 TEXT，需转为 i64
                    // parse 失败显性化（fail-fast）：脏数据不应静默关联到 user 0
                    let login_id_i64: i64 = login_id.parse().map_err(|e| {
                        GarrisonError::Dao(format!(
                            "jwt-refresh-login-id-parse-failed::{}::{}",
                            login_id, e
                        ))
                    })?;

                    Ok(Some(RefreshTokenRecord {
                        token_hash,
                        parent_token_hash,
                        login_id: login_id_i64,
                        tenant_id,
                        key_version: key_version as u32,
                        expires_at,
                        revoked: revoked == 1,
                        created_at,
                        rotated_at,
                        client_id,
                        scopes,
                        username,
                        user_id,
                    }))
                },
                None => Ok(None),
            }
        }

        /// 宽限窗口兑现尝试（重用检测命中路径）。
        ///
        /// 资格判定：窗口开启 + 该 token 的 `rotated_at` 在窗口内 + 子类型具备
        /// 兑现资格——`RecentPrev`（直接子代即胜者新 token）；无任何子代的
        /// `StaleLineage`（轮换在途候选：胜者已原子消费、子代尚未落库）。
        /// `OrphanedBranch` 及已有子代的 `StaleLineage`（链吊销后再呈现）不兑现。
        async fn try_grace_redemption(
            &self,
            old_hash: &str,
            subtype: RefreshTokenReuseSubtype,
        ) -> GarrisonResult<Option<(String, String)>> {
            if self.grace_period_secs <= 0 {
                return Ok(None);
            }
            // OrphanedBranch 资格恒为 false（静态判定），先于任何 IO 返回，
            // 避免错误路径浪费池获取与查询
            if matches!(subtype, RefreshTokenReuseSubtype::OrphanedBranch) {
                return Ok(None);
            }
            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;
            let rotated_at = Self::fetch_rotated_at(conn, old_hash).await?;
            let in_window =
                matches!(rotated_at, Some(t) if Self::now_unix() - t <= self.grace_period_secs);
            if !in_window {
                return Ok(None);
            }
            let eligible = match subtype {
                RefreshTokenReuseSubtype::RecentPrev => true,
                RefreshTokenReuseSubtype::OrphanedBranch => false,
                RefreshTokenReuseSubtype::StaleLineage => {
                    !Self::has_children(conn, old_hash).await?
                },
            };
            if !eligible {
                return Ok(None);
            }
            // 轮询等待目标纯在进程内存，先释放池连接再等待——竞态风暴下
            // N-1 个落败方不各钉住一条连接至 deadline（250ms）
            drop(session);
            Ok(self.await_grace_redemption(old_hash).await)
        }

        /// 轮询宽限凭据直至出现或竞态等待截止。
        async fn await_grace_redemption(&self, old_hash: &str) -> Option<(String, String)> {
            let deadline = std::time::Instant::now() + GRACE_RACE_DEADLINE;
            loop {
                if let Some(redeemed) = self.redeem_grace_entry(old_hash) {
                    return Some(redeemed);
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(GRACE_RACE_POLL).await;
            }
        }

        /// 登记宽限兑现凭据（轮换成功后调用；顺带清理窗口外过期条目）。
        fn record_grace_entry(
            &self,
            old_hash: &str,
            new_refresh: &str,
            login_id: &str,
            rotated_at: i64,
        ) {
            if self.grace_period_secs <= 0 {
                return;
            }
            let mut entries = self.grace_entries.lock().expect("grace_entries 锁不应中毒");
            entries.retain(|_, entry| rotated_at - entry.rotated_at <= self.grace_period_secs);
            entries.insert(
                old_hash.to_string(),
                GraceEntry {
                    new_refresh: new_refresh.to_string(),
                    login_id: login_id.to_string(),
                    rotated_at,
                    uses: 0,
                },
            );
        }

        /// 兑现宽限凭据：窗口内且预算未耗尽时返回既有 (new_refresh, login_id)
        /// 并占用一次预算；超期/预算耗尽/无凭据返回 `None`。
        fn redeem_grace_entry(&self, old_hash: &str) -> Option<(String, String)> {
            if self.grace_period_secs <= 0 {
                return None;
            }
            let now = Self::now_unix();
            let mut entries = self.grace_entries.lock().expect("grace_entries 锁不应中毒");
            let entry = entries.get_mut(old_hash)?;
            if now - entry.rotated_at > self.grace_period_secs || entry.uses >= self.grace_max_uses
            {
                return None;
            }
            entry.uses += 1;
            Some((entry.new_refresh.clone(), entry.login_id.clone()))
        }

        /// 查询单条记录的 `rotated_at`（轮换被消费的时刻）；记录不存在或从未
        /// 被轮换返回 `None`。
        async fn fetch_rotated_at(
            conn: &DatabaseConnection,
            token_hash: &str,
        ) -> GarrisonResult<Option<i64>> {
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT rotated_at FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(token_hash.to_string()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
            match row {
                Some(row) => row
                    .try_get::<Option<i64>>("", "rotated_at")
                    .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e))),
                None => Ok(None),
            }
        }

        /// 判断是否存在以该 hash 为父代的子代记录。
        async fn has_children(conn: &DatabaseConnection, token_hash: &str) -> GarrisonResult<bool> {
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS cnt FROM refresh_tokens WHERE parent_token_hash = ?",
                vec![Value::String(Some(token_hash.to_string()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?
                .ok_or_else(|| GarrisonError::Dao("jwt-refresh-count-empty::".to_string()))?;
            let count: i64 = row
                .try_get("", "cnt")
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
            Ok(count > 0)
        }

        /// 重用处置分派：按子类型与 `reuse_behaviour` 决定响应错误。
        ///
        /// - StaleLineage：恒吊销整条链 + `TokenRevoked`（盗用语义，不受配置影响）
        /// - RecentPrev / OrphanedBranch + `TheftDetected`：吊销整条链 + `TokenRevoked`
        /// - RecentPrev / OrphanedBranch + `Unauthorised`：仅 `InvalidToken`，不吊销链
        ///
        /// 返回 `Ok(应返回给调用方的错误)`；吊销/查询中途的 SQL 失败以 `Err`
        /// 透传（错误显性化，不吞并）。
        async fn dispose_reuse(
            &self,
            old_hash: &str,
            subtype: RefreshTokenReuseSubtype,
        ) -> GarrisonResult<GarrisonError> {
            let theft = match subtype {
                RefreshTokenReuseSubtype::StaleLineage => true,
                RefreshTokenReuseSubtype::RecentPrev | RefreshTokenReuseSubtype::OrphanedBranch => {
                    matches!(self.reuse_behaviour, RecentReuseBehaviour::TheftDetected)
                },
            };
            if theft {
                self.revoke_chain(old_hash).await?;
                return Ok(GarrisonError::TokenRevoked(
                    "refresh token reuse detected, chain revoked".to_string(),
                ));
            }
            Ok(GarrisonError::InvalidToken(
                "jwt-refresh-reuse-rejected::unauthorised".to_string(),
            ))
        }

        /// 检测 token 重用并做三级分类。
        ///
        /// # 参数
        /// - `token_hash`: 已 SHA-256 哈希的 token hash（非原始 token）
        ///
        /// # 返回
        /// - `Ok(None)`: token 不存在或未 revoked（非重用；不存在视为"未签发"）
        /// - `Ok(Some(RecentPrev))`: 提交 hash 命中存活链头记录的
        ///   `parent_token_hash`（回溯 1 跳）
        /// - `Ok(Some(OrphanedBranch))`: 命中更早祖先（回溯 >1 跳）
        /// - `Ok(Some(StaleLineage))`: 无存活血缘（无子代，或后代全部已吊销）
        /// - `Err(GarrisonError::Dao)`: SQL 查询失败
        ///
        /// 回溯深度封顶 [`REUSE_LINEAGE_MAX_DEPTH`]：达到上限仍存在子代链时按
        /// `OrphanedBranch` 处置——能沿子代链走这么深本身就证明血缘存在。
        pub async fn detect_reuse(
            &self,
            token_hash: &str,
        ) -> GarrisonResult<Option<RefreshTokenReuseSubtype>> {
            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;

            // 不存在 → None（未签发，不算重用）；存在且 revoked=0 → None（未消费）
            let revoked = match Self::fetch_revoked(conn, token_hash).await? {
                Some(revoked) => revoked,
                None => return Ok(None),
            };
            if revoked != 1 {
                return Ok(None);
            }
            Ok(Some(Self::classify_lineage(conn, token_hash).await?))
        }

        /// 查询单条记录的 `revoked` 字段；记录不存在返回 `None`。
        async fn fetch_revoked(
            conn: &dbnexus::sea_orm::DatabaseConnection,
            token_hash: &str,
        ) -> GarrisonResult<Option<i64>> {
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(token_hash.to_string()))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
            match row {
                Some(row) => row
                    .try_get::<i64>("", "revoked")
                    .map(Some)
                    .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e))),
                None => Ok(None),
            }
        }

        /// 沿子代方向逐跳回溯，定位提交 hash 与存活链头的距离。
        ///
        /// BFS 逐层展开子代（`parent_token_hash` 反查）：任一层出现 `revoked=0`
        /// 的记录即存活链头——第 1 层 → `RecentPrev`，更深层 → `OrphanedBranch`；
        /// 展开耗尽（无子代或子代全 revoked）→ `StaleLineage`。
        async fn classify_lineage(
            conn: &dbnexus::sea_orm::DatabaseConnection,
            token_hash: &str,
        ) -> GarrisonResult<RefreshTokenReuseSubtype> {
            let mut frontier = vec![token_hash.to_string()];
            for hop in 1..=REUSE_LINEAGE_MAX_DEPTH {
                let mut next = Vec::new();
                for parent in &frontier {
                    let stmt = Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        "SELECT token_hash, revoked FROM refresh_tokens \
                         WHERE parent_token_hash = ?",
                        vec![Value::String(Some(parent.clone()))],
                    );
                    let rows = conn.query_all_raw(stmt).await.map_err(|e| {
                        GarrisonError::Dao(format!("jwt-refresh-select-child::{}", e))
                    })?;
                    for row in rows {
                        let child_hash: String = row
                            .try_get("", "token_hash")
                            .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                        let child_revoked: i64 = row
                            .try_get("", "revoked")
                            .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                        if child_revoked == 0 {
                            return Ok(if hop == 1 {
                                RefreshTokenReuseSubtype::RecentPrev
                            } else {
                                RefreshTokenReuseSubtype::OrphanedBranch
                            });
                        }
                        next.push(child_hash);
                    }
                }
                if next.is_empty() {
                    return Ok(RefreshTokenReuseSubtype::StaleLineage);
                }
                frontier = next;
            }
            Ok(RefreshTokenReuseSubtype::OrphanedBranch)
        }

        /// 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
        ///
        /// 语义：reuse detection 命中 old_token 后，old_token 之后签发的所有
        /// 后代 token（即 parent_token_hash 链上以 old_token 为根的子树）
        /// 都应被吊销，防止攻击者继续使用被盗链。
        ///
        /// # 参数
        /// - `token_hash`: 起点 token hash（已 SHA-256 哈希）
        ///
        /// # 算法（迭代 + 栈，避免 async 递归 Box::pin 复杂度）
        /// 1. 把 `token_hash` 入栈
        /// 2. 出栈一个 hash，UPDATE 它 revoked=1
        /// 3. 查所有 `parent_token_hash == hash` 的 record（子代），入栈
        /// 4. 重复直到栈空
        ///
        /// # 并发窗口（剩余风险，文档化）
        ///
        /// `rotate` 的原子消费保证：子 record 只能在其 parent 被置 `revoked=1`
        /// 之后 INSERT。因此本方法"UPDATE 后再扫子代"的循环可能漏掉一个
        /// 已抢到消费权、INSERT 尚未落库的在途子代——该子代落下后其 parent
        /// 必已 revoked，后续对它的任何 `validate`/`rotate` 均可见链被破坏
        /// 状态；如需强一致收口，调用方应在 reuse 响应路径上层加互斥
        /// （与 apikey rotate 同风格：库层不内置分布式锁）。
        ///
        /// # 错误
        /// - `GarrisonError::Dao`: SQL 查询/UPDATE 失败
        pub async fn revoke_chain(&self, token_hash: &str) -> GarrisonResult<()> {
            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-get-conn::{}", e)))?;

            let mut stack = vec![token_hash.to_string()];
            while let Some(hash) = stack.pop() {
                // UPDATE current revoked=1
                let update_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                    vec![Value::String(Some(hash.clone()))],
                );
                conn.execute_raw(update_stmt)
                    .await
                    .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-update::{}", e)))?;

                // 链吊销同步失效宽限凭据（防吊销后经窗口兑现复活 token）；
                // 中毒即 fail-fast——安全相关清理不可静默跳过（与文件内其余
                // 锁使用点一致）。作用域块即时释放 guard，不得跨 await 持锁。
                {
                    let mut entries = self.grace_entries.lock().expect("grace_entries 锁不应中毒");
                    entries.remove(&hash);
                }

                // 查子代（parent_token_hash == hash）
                let select_stmt = Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT token_hash FROM refresh_tokens WHERE parent_token_hash = ?",
                    vec![Value::String(Some(hash))],
                );
                let rows = conn
                    .query_all_raw(select_stmt)
                    .await
                    .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-select-child::{}", e)))?;
                for row in rows {
                    let child_hash: String = row
                        .try_get("", "token_hash")
                        .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-query::{}", e)))?;
                    stack.push(child_hash);
                }
            }
            Ok(())
        }

        /// 清理已撤销且已过期的 refresh token 记录。
        ///
        /// 删除满足以下**全部条件**的记录：
        /// - `revoked = 1`（已撤销）
        /// - `expires_at < now - grace_period`（过期超过 7 天）
        ///
        /// 不删除未撤销但已过期的 token（保留审计价值）。
        /// 不删除已撤销但未过期的 token（grace period 内可能仍需追溯）。
        ///
        /// # 返回
        /// 实际删除的记录数。
        ///
        /// # 错误
        /// - `GarrisonError::Dao`: SQL 执行失败
        ///
        /// # 调用频率
        /// 由调用方决定（建议与 session cleanup 同周期调度）。
        pub async fn cleanup_expired(&self) -> GarrisonResult<usize> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("jwt-refresh-cleanup-get-session::{}", e))
            })?;
            let conn = session
                .connection()
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-cleanup-get-conn::{}", e)))?;

            // grace period = 7 天（与 refresh token TTL 一致）
            let threshold = Self::now_unix() - 7 * 86400;
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "DELETE FROM refresh_tokens WHERE revoked = 1 AND expires_at < ?",
                vec![Value::BigInt(Some(threshold))],
            );
            let result = conn
                .execute_raw(stmt)
                .await
                .map_err(|e| GarrisonError::Dao(format!("jwt-refresh-cleanup-delete::{}", e)))?;

            Ok(result.rows_affected() as usize)
        }
    }
}

#[cfg(feature = "db-sqlite")]
pub use service::RefreshTokenRotation;

#[cfg(test)]
mod tests {
    use super::*;

    /// `RefreshTokenRecord` 构造测试（hash chain 字段可读）。
    ///
    /// 断言所有字段可正确初始化与读取，包括：
    /// - `token_hash`: 新 token 的 SHA-256 哈希
    /// - `parent_token_hash`: 旧 token 的哈希（首次签发为 None）
    /// - `login_id` / `tenant_id`: 多租户隔离
    /// - `key_version`: 密钥轮换版本号
    /// - `expires_at` / `created_at`: 时间戳
    /// - `revoked`: 是否已撤销（防重放）
    #[test]
    fn refresh_token_record_constructs_with_hash_chain_fields() {
        let record = RefreshTokenRecord {
            token_hash: "abc".to_string(),
            parent_token_hash: Some("def".to_string()),
            login_id: 1,
            tenant_id: 0,
            key_version: 1,
            expires_at: 9999,
            revoked: false,
            created_at: 0,
            rotated_at: None,
            client_id: None,
            scopes: None,
            username: None,
            user_id: None,
        };
        assert_eq!(record.token_hash, "abc");
        assert_eq!(record.parent_token_hash, Some("def".to_string()));
        assert_eq!(record.login_id, 1);
        assert_eq!(record.tenant_id, 0);
        assert_eq!(record.key_version, 1);
        assert_eq!(record.expires_at, 9999);
        assert!(!record.revoked);
        assert_eq!(record.created_at, 0);
        assert_eq!(record.rotated_at, None);
        // OAuth2 扩展字段默认为 None
        assert_eq!(record.client_id, None);
        assert_eq!(record.scopes, None);
        assert_eq!(record.username, None);
        assert_eq!(record.user_id, None);
    }

    /// OAuth2 扩展字段为必填：JSON 缺失任一字段即反序列化失败（fail-closed）。
    #[test]
    fn refresh_token_record_requires_oauth2_fields() {
        let json = r#"{
            "token_hash": "abc123",
            "parent_token_hash": null,
            "login_id": 42,
            "tenant_id": 1,
            "key_version": 2,
            "expires_at": 1700000000,
            "revoked": false,
            "created_at": 1699000000
        }"#;
        let result = serde_json::from_str::<RefreshTokenRecord>(json);
        assert!(
            result.is_err(),
            "缺失 OAuth2 扩展字段的 JSON 应反序列化失败，实际: {:?}",
            result
        );
    }

    /// →Green: 含 OAuth2 扩展字段的 JSON 序列化-反序列化往返一致。
    #[test]
    fn refresh_token_record_new_json_roundtrip() {
        let record = RefreshTokenRecord {
            token_hash: "new_hash".to_string(),
            parent_token_hash: Some("old_hash".to_string()),
            login_id: 100,
            tenant_id: 5,
            key_version: 3,
            expires_at: 1800000000,
            revoked: false,
            created_at: 1700000000,
            rotated_at: Some(1699999000),
            client_id: Some("client_123".to_string()),
            scopes: Some("read write admin".to_string()),
            username: Some("alice".to_string()),
            user_id: Some(42),
        };
        let json = serde_json::to_string(&record).expect("序列化应成功");
        let deserialized: RefreshTokenRecord = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(record, deserialized);
    }
}

// ============================================================================
// db-sqlite 集成测试（_tokens 表迁移 + rotate 服务）
// ============================================================================

#[cfg(all(test, feature = "protocol-jwt", feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::{RefreshTokenReuseSubtype, RefreshTokenRotation};
    use crate::config::RecentReuseBehaviour;
    use crate::dao::{init_dbnexus, GarrisonMigration};
    use crate::error::GarrisonError;
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use dbnexus::DbPool;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    // ========================================================================
    // _tokens 表迁移验证
    // ========================================================================

    /// 验证 SQLite 迁移加载 `003_refresh_tokens.sql` 后
    /// `refresh_tokens` 表存在。
    ///
    /// 惯例优先：SQL 文件放 `migrations/sqlite/core/003_refresh_tokens.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制（与 002_role_hierarchy.sql 同惯例），
    /// 而非 原描述的 `src/dao/repository/sqlite/refresh_tokens.sql`。
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_tokens_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='refresh_tokens'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "refresh_tokens 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }

    // ========================================================================
    // 辅助函数（+ rotate 测试用）
    // ========================================================================

    /// 计算 SHA-256 并返回 hex 字符串。
    fn sha256_hex(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 向 refresh_tokens 表插入一条记录。
    async fn insert_refresh_token(
        pool: &DbPool,
        token_hash: &str,
        parent_token_hash: Option<&str>,
        login_id: i64,
        tenant_id: i64,
        key_version: u32,
        expires_at: i64,
        revoked: i64,
    ) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO refresh_tokens (token_hash, parent_token_hash, login_id, tenant_id, key_version, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::String(Some(token_hash.to_string())),
                Value::String(parent_token_hash.map(|s| s.to_string())),
                Value::BigInt(Some(login_id)),
                Value::BigInt(Some(tenant_id)),
                Value::BigInt(Some(key_version as i64)),
                Value::BigInt(Some(expires_at)),
                Value::BigInt(Some(revoked)),
                Value::BigInt(Some(0)),
            ],
        );
        conn.execute_raw(stmt).await.expect("INSERT 应成功");
    }

    /// 查询 record 的 revoked 字段。
    async fn query_revoked(pool: &DbPool, token_hash: &str) -> i64 {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        row.try_get::<i64>("", "revoked").unwrap()
    }

    /// 查询 record 的 (parent_token_hash, revoked)。
    async fn query_record(pool: &DbPool, token_hash: &str) -> (Option<String>, i64) {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT parent_token_hash, revoked FROM refresh_tokens WHERE token_hash = ?",
            vec![Value::String(Some(token_hash.to_string()))],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .unwrap()
            .expect("record 应存在");
        let parent: Option<String> = row.try_get("", "parent_token_hash").ok();
        let revoked: i64 = row.try_get("", "revoked").unwrap();
        (parent, revoked)
    }

    // ========================================================================
    // 测试
    // ========================================================================

    /// `rotate` 插入新 token 并标记旧 token 已消费。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（模拟已签发的 refresh token）
    /// 2. 调用 `rotate(old_token)` 返回 (new_access, new_refresh)
    /// 3. 断言 old_token 的 record revoked=1
    /// 4. 断言 new_refresh 的 record 已插入，parent_token_hash == SHA-256(old_token)
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_inserts_new_token_and_marks_old_consumed() {
        let pool = setup_db().await;

        // 预先 INSERT old_token record
        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        // 构造 RefreshTokenRotation（持有 pool + jwt_handler + key_version）
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate
        let (new_access, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");
        assert!(!new_access.is_empty(), "new_access 应非空");
        assert!(!new_refresh.is_empty(), "new_refresh 应非空");

        // 断言 old_token revoked=1
        let old_revoked = query_revoked(&pool, &old_hash).await;
        assert_eq!(old_revoked, 1, "old_token 应标记为 revoked");

        // 断言 new_refresh 的 record 已插入，parent_token_hash == old_hash
        let new_hash = sha256_hex(&new_refresh);
        let (parent, revoked) = query_record(&pool, &new_hash).await;
        assert_eq!(
            parent,
            Some(old_hash),
            "new record 的 parent_token_hash 应等于 old_hash"
        );
        assert_eq!(revoked, 0, "new record 应未 revoked");
    }

    // ========================================================================
    // _reuse 测试
    // ========================================================================

    /// `detect_reuse` 在 token 已被消费（revoked=1）时检出重用。
    ///
    /// 流程：
    /// 1. 预先 INSERT old_token record（revoked=0）
    /// 2. 调用 `rotate(old_token)` → old_token 标记为 revoked=1
    /// 3. 调用 `detect_reuse(SHA-256(old_token))` → 断言返回 `Some(_)`（已消费）
    /// 4. 用 new_refresh 的 hash 调用 `detect_reuse` → 断言返回 `None`（未消费）
    #[tokio::test(flavor = "multi_thread")]
    async fn detect_reuse_returns_true_when_token_already_consumed() {
        let pool = setup_db().await;

        let old_token = "old_token_value";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // rotate 后 old_token 应 revoked=1
        let (_, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");

        // detect_reuse(old_hash) → Some（已被消费）
        let reused = rotation
            .detect_reuse(&old_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(reused.is_some(), "已 revoked 的 token 应检测为 reuse");

        // detect_reuse(new_hash) → None（未消费）
        let new_hash = sha256_hex(&new_refresh);
        let new_reused = rotation
            .detect_reuse(&new_hash)
            .await
            .expect("detect_reuse 应成功");
        assert!(new_reused.is_none(), "未 revoked 的 token 不应检测为 reuse");
    }

    // ========================================================================
    // 重用三级分类测试
    // ========================================================================

    /// 提交 token 的 hash 命中存活链头记录的 `parent_token_hash`（直接子代，
    /// 回溯 1 跳）→ `RecentPrev`。
    ///
    /// 场景：客户端与攻击者（或另一标签页）同时持有 t2 的前身 t1，t1 已被
    /// 一次合法 rotate 消费、其子代 t2 仍存活。
    #[tokio::test(flavor = "multi_thread")]
    async fn recent_prev_detected_when_parent_hash_matches() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // 自然链：issue t1 → rotate 得 t2（链头 t2 存活，t1 已消费）
        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, _t2) = rotation.rotate(&t1).await.expect("rotate 应成功");

        let t1_hash = sha256_hex(&t1);
        let subtype = rotation
            .detect_reuse(&t1_hash)
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(
            subtype,
            Some(RefreshTokenReuseSubtype::RecentPrev),
            "命中存活链头的 parent_token_hash 应分类为 RecentPrev，实际: {subtype:?}"
        );
    }

    /// 提交 token 命中更早祖先（回溯 >1 跳才到达存活链头）→ `OrphanedBranch`。
    ///
    /// 场景：链 t1 → t2 → t3（链头 t3）；提交 t2 为 RecentPrev（1 跳），
    /// 提交 t1 需回溯 2 跳 → OrphanedBranch。
    #[tokio::test(flavor = "multi_thread")]
    async fn orphaned_branch_detected_when_ancestor_hash_matches() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("第一次 rotate 应成功");
        let (_, _t3) = rotation.rotate(&t2).await.expect("第二次 rotate 应成功");

        // t2 是链头 t3 的直接父代 → RecentPrev（1 跳）
        let t2_hash = sha256_hex(&t2);
        let t2_subtype = rotation
            .detect_reuse(&t2_hash)
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(
            t2_subtype,
            Some(RefreshTokenReuseSubtype::RecentPrev),
            "1 跳祖先应分类为 RecentPrev，实际: {t2_subtype:?}"
        );

        // t1 距链头 2 跳 → OrphanedBranch
        let t1_hash = sha256_hex(&t1);
        let t1_subtype = rotation
            .detect_reuse(&t1_hash)
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(
            t1_subtype,
            Some(RefreshTokenReuseSubtype::OrphanedBranch),
            ">1 跳祖先应分类为 OrphanedBranch，实际: {t1_subtype:?}"
        );
    }

    /// 无血缘关系 → `StaleLineage`；未消费/未知 hash → `None`（非重用）。
    ///
    /// StaleLineage 的两种形态：
    /// - 孤立已消费 token：无任何子代（如吊销后/半成品清理后）
    /// - 整链已吊销后的再呈现：子代存在但全部 revoked（无存活后代）
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_lineage_when_no_relation() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // (a) 孤立已消费 token：revoked=1 且无子代
        let orphan_hash = sha256_hex("orphan_token_value");
        insert_refresh_token(&pool, &orphan_hash, None, 1, 0, 1, 9999, 1).await;
        let orphan_subtype = rotation
            .detect_reuse(&orphan_hash)
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(
            orphan_subtype,
            Some(RefreshTokenReuseSubtype::StaleLineage),
            "无子代的已消费 token 应分类为 StaleLineage，实际: {orphan_subtype:?}"
        );

        // (b) 整链吊销后的再呈现：t1 → t2 后 revoke_chain，t1 的后代全部 revoked
        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, _t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t1_hash = sha256_hex(&t1);
        rotation
            .revoke_chain(&t1_hash)
            .await
            .expect("revoke_chain 应成功");
        let revoked_subtype = rotation
            .detect_reuse(&t1_hash)
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(
            revoked_subtype,
            Some(RefreshTokenReuseSubtype::StaleLineage),
            "整链吊销后的再呈现应分类为 StaleLineage，实际: {revoked_subtype:?}"
        );

        // (c) 未消费的链头 → None（非重用）
        let t3 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let live_subtype = rotation
            .detect_reuse(&sha256_hex(&t3))
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(live_subtype, None, "存活 token 不应检出重用");

        // (d) 未知 hash → None（未签发，不算重用）
        let unknown_subtype = rotation
            .detect_reuse(&sha256_hex("never_issued_token"))
            .await
            .expect("detect_reuse 应成功");
        assert_eq!(unknown_subtype, None, "未知 token 不应检出重用");
    }

    /// `Unauthorised` 配置下 RecentPrev 重用仅拒绝本次请求，不吊销存活链。
    ///
    /// 对照：默认 `TheftDetected` 下同场景返回 `TokenRevoked` 且整链吊销
    /// （见 `rotate_with_reuse_detection_revokes_chain`）。
    #[tokio::test(flavor = "multi_thread")]
    async fn recent_prev_disposal_unauthorised_keeps_chain() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_reuse_behaviour(RecentReuseBehaviour::Unauthorised);

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);

        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidToken(ref msg)) if msg.contains("unauthorised")),
            "Unauthorised 处置应返回 InvalidToken，实际: {:?}",
            result
        );
        // 存活链头未被吊销
        let t2_revoked = query_revoked(&pool, &t2_hash).await;
        assert_eq!(t2_revoked, 0, "Unauthorised 处置不得吊销存活链头");
    }

    /// `Unauthorised` 配置下 OrphanedBranch（>1 跳祖先）同样仅拒绝、不吊销。
    #[tokio::test(flavor = "multi_thread")]
    async fn orphaned_branch_disposal_unauthorised_keeps_chain() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_reuse_behaviour(RecentReuseBehaviour::Unauthorised);

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("第一次 rotate 应成功");
        let (_, t3) = rotation.rotate(&t2).await.expect("第二次 rotate 应成功");
        let t2_hash = sha256_hex(&t2);
        let t3_hash = sha256_hex(&t3);

        // t1 距链头 t3 两跳 → OrphanedBranch → Unauthorised 处置
        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidToken(_))),
            "OrphanedBranch 在 Unauthorised 下应返回 InvalidToken，实际: {:?}",
            result
        );
        // t2 已被第二次 rotate 合法消费（revoked=1 与处置无关）；
        // 链吊销会击穿存活链头 t3——t3 存活即证明未发生链吊销
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应保持 rotate 时的已消费态"
        );
        assert_eq!(
            query_revoked(&pool, &t3_hash).await,
            0,
            "存活链头不得被吊销"
        );
    }

    // ========================================================================
    // 宽限窗口测试
    // ========================================================================

    /// 单连接 SQLite 内存池（并发测试需全 task 共享同一内存库）。
    async fn setup_single_connection_db() -> DbPool {
        let config = dbnexus::DbConfig {
            url: "sqlite::memory:".to_string(),
            pool_config: dbnexus::PoolConfig {
                max_connections: 1,
                min_connections: 1,
                acquire_timeout: 15_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let pool = dbnexus::DbPool::with_config(config)
            .await
            .expect("初始化单连接 dbnexus 池应成功");
        let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// 宽限窗口内同一旧 token 并发双刷得到同一新 token（交错测试）。
    ///
    /// 两个 task 同时 rotate 同一旧 token：无论交错落在检测前/消费竞态/检测后
    /// 哪条路径，双方都拿到胜者签发的同一新 refresh token（不重旋转），且仅
    /// 存在一个子代记录。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn grace_window_concurrent_double_refresh_returns_same_token() {
        let pool = setup_single_connection_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation = Arc::new(
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_grace_window(60, 1),
        );

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let t1_hash = sha256_hex(&t1);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let rotation = rotation.clone();
            let token = t1.clone();
            set.spawn(async move { rotation.rotate(&token).await });
        }
        let mut refreshes = Vec::new();
        while let Some(result) = set.join_next().await {
            let (_, refresh) = result
                .expect("并发 rotate task 不应 panic")
                .expect("宽限窗口内并发双刷应成功");
            refreshes.push(refresh);
        }
        assert_eq!(refreshes.len(), 2, "双方都应成功");
        assert_eq!(
            refreshes[0], refreshes[1],
            "宽限窗口内并发双刷应得到同一新 token"
        );

        // 不重旋转：旧 token 恰有一个子代记录
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS cnt FROM refresh_tokens WHERE parent_token_hash = ?",
            vec![Value::String(Some(t1_hash))],
        );
        let row = conn.query_one_raw(stmt).await.unwrap().unwrap();
        assert_eq!(
            row.try_get::<i64>("", "cnt").unwrap(),
            1,
            "不应产生重复子代"
        );
    }

    /// 窗口外旧 token 按重用处置（默认配置即盗用：吊销整条链）。
    #[tokio::test(flavor = "multi_thread")]
    async fn grace_window_expired_old_token_follows_reuse_disposal() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_grace_window(60, 1);

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);

        // 把 t1 的 rotated_at 拨回窗口外（2 倍窗口之前）
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时钟应晚于 UNIX_EPOCH")
            .as_secs() as i64;
        let backdate = now - 120;
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ?",
            vec![
                Value::BigInt(Some(backdate)),
                Value::String(Some(sha256_hex(&t1))),
            ],
        );
        conn.execute_raw(stmt).await.expect("backdate 应成功");
        drop(session);

        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "窗口外旧 token 应按盗用处置，实际: {:?}",
            result
        );
        assert_eq!(query_revoked(&pool, &t2_hash).await, 1, "链应被吊销");
    }

    /// 宽限兑现预算耗尽后，窗口内重放按重用处置（默认 TheftDetected 吊销整链）；
    /// 「不吊销链」仅适用于并发落败方（CAS 未抢到消费权）路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn grace_window_exhausted_uses_follow_disposal() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_grace_window(60, 1);

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);

        // 第 1 次窗口内重放：预算 1，兑现既有新 token
        let (_, graced) = rotation.rotate(&t1).await.expect("预算内重放应兑现");
        assert_eq!(graced, t2, "窗口内兑现应返回既有新 token");
        // 第 2 次重放：预算耗尽 → 按重用处置
        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "预算耗尽后应按盗用处置，实际: {:?}",
            result
        );
        assert_eq!(query_revoked(&pool, &t2_hash).await, 1, "链应被吊销");
    }

    /// 在途胜者竞态（确定性构造）：胜者已完成原子消费但子代未落库的窗口内，
    /// 后续重放命中宽限兑现拿到与胜者相同的既有新 token（不重旋转）。
    ///
    /// 构造方式：正常 rotate 后 DELETE 子代行——等价于「胜者已 CAS + 登记凭据、
    /// 子代 INSERT 在途」的交错态（多连接生产池下真实存在，单连接测试池不可达，
    /// 见 grace_window_concurrent 说明）。断言走 try_grace_redemption 的
    /// StaleLineage 在途候选臂（无子代 → eligible）而非平凡的重放处置。
    #[tokio::test(flavor = "multi_thread")]
    async fn grace_window_inflight_winner_deleted_child_redeems_same_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation = Arc::new(
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_grace_window(60, 1),
        );

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let t1_hash = sha256_hex(&t1);
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);

        // 模拟在途态：删除胜者子代行（胜者已消费 + 已登记凭据）
        {
            let session = pool.get_session("admin").await.unwrap();
            let conn = session.connection().unwrap();
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "DELETE FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(t2_hash.clone()))],
            );
            conn.execute_raw(stmt).await.expect("删除子代应成功");
        }

        // 窗口内重放：无子代 → StaleLineage 在途候选 → 兑现既有新 token
        let (_, graced) = rotation.rotate(&t1).await.expect("在途竞态兑现应成功");
        assert_eq!(
            graced, t2,
            "在途胜者窗口内的重放应兑现与胜者相同的既有新 token"
        );

        // 不重旋转：子代仍缺失（兑现不产生新记录）
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS cnt FROM refresh_tokens WHERE parent_token_hash = ?",
            vec![Value::String(Some(t1_hash))],
        );
        let row = conn.query_one_raw(stmt).await.unwrap().unwrap();
        assert_eq!(row.try_get::<i64>("", "cnt").unwrap(), 0, "兑现不应重旋转");
    }

    /// 宽限竞态等待超时：窗口内已消费但无凭据可兑现（胜者未登记即崩溃 /
    /// 多实例另一实例签发），轮询至 GRACE_RACE_DEADLINE 后放弃并按重用处置。
    #[tokio::test(flavor = "multi_thread")]
    async fn grace_window_race_wait_timeout_follows_disposal() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_grace_window(60, 1);

        // 手工构造窗口内已消费态：revoked=1 + rotated_at=now，但本进程宽限表
        // 无凭据（胜者崩溃 / 多实例下凭据在另一实例）
        let old_token = "inflight-lost-grace-entry-token";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 1, 1, 9999, 1).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        {
            let session = pool.get_session("admin").await.unwrap();
            let conn = session.connection().unwrap();
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ?",
                vec![
                    Value::BigInt(Some(now)),
                    Value::String(Some(old_hash.clone())),
                ],
            );
            conn.execute_raw(stmt)
                .await
                .expect("写入 rotated_at 应成功");
        }

        let result = rotation.rotate(old_token).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "竞态等待超时后应按盗用处置，实际: {:?}",
            result
        );
        assert_eq!(query_revoked(&pool, &old_hash).await, 1, "链应被吊销");
    }

    /// 回归锁：默认配置（宽限窗口关闭）行为与现状一致——窗口内重放按盗用
    /// 处置返回 `TokenRevoked` 并吊销整条链，绝不兑现既有新 token。
    #[tokio::test(flavor = "multi_thread")]
    async fn grace_disabled_by_default_keeps_theft_semantics() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);

        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "默认配置下窗口内重放应按盗用处置，实际: {:?}",
            result
        );
        assert_eq!(query_revoked(&pool, &t2_hash).await, 1, "链应被吊销");
    }

    /// 旋转中途写失败补偿：INSERT 失败删除半成品行并回退消费，原链仍可用。
    ///
    /// 注入方式：BEFORE INSERT 触发器 RAISE(ABORT)——原子消费（UPDATE）已
    /// 成功而子代落库失败的真实中间态。断言：
    /// 1. 错误显性（Dao 且标注 rolled-back，不吞并注入原因）；
    /// 2. 无残留半成品子代（parent_token_hash = 旧 hash 的行数为 0）；
    /// 3. 旧 token 恢复 revoked=0 / rotated_at=NULL，可再次正常轮换。
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_insert_failure_compensates_and_keeps_chain_usable() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let t1_hash = sha256_hex(&t1);

        let trigger_sql = "CREATE TRIGGER fail_rotate_insert BEFORE INSERT ON refresh_tokens \
             BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;";
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            trigger_sql,
            vec![],
        ))
        .await
        .expect("创建注入触发器应成功");
        drop(session);

        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref msg)) if msg.contains("rolled-back")),
            "注入失败应返回标注 rolled-back 的 Dao 错误，实际: {:?}",
            result
        );

        // 断言无残留半成品子代 + 原 token 已恢复可用
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let children = conn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS cnt FROM refresh_tokens WHERE parent_token_hash = ?",
                vec![Value::String(Some(t1_hash.clone()))],
            ))
            .await
            .expect("COUNT 应成功")
            .expect("应有结果行");
        assert_eq!(
            children.try_get::<i64>("", "cnt").unwrap(),
            0,
            "补偿后不得残留半成品子代"
        );
        let restored = conn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT revoked, rotated_at FROM refresh_tokens WHERE token_hash = ?",
                vec![Value::String(Some(t1_hash.clone()))],
            ))
            .await
            .expect("查询应成功")
            .expect("原 token 记录应存在");
        assert_eq!(
            restored.try_get::<i64>("", "revoked").unwrap(),
            0,
            "原 token 应恢复 revoked=0"
        );
        let rotated_at: Option<i64> = restored.try_get("", "rotated_at").unwrap();
        assert_eq!(rotated_at, None, "原 token 的 rotated_at 应回退为 NULL");
        drop(session);

        // 原链仍可用：移除触发器后再次轮换成功
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DROP TRIGGER fail_rotate_insert",
            vec![],
        ))
        .await
        .expect("移除注入触发器应成功");
        drop(session);
        let (_, retried) = rotation.rotate(&t1).await.expect("补偿后原链应可再次轮换");
        assert!(!retried.is_empty(), "重试轮换应产出新 token");
    }

    /// StaleLineage 恒按盗用处理：即使配置为 `Unauthorised` 仍吊销整条链并
    /// 返回 `TokenRevoked`（配置不可改变该行为）。
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_lineage_disposal_overrides_unauthorised() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)))
                .with_reuse_behaviour(RecentReuseBehaviour::Unauthorised);

        let t1 = rotation
            .issue("client", Some(1), &[], None, 1, 0, 9999)
            .await
            .expect("issue 应成功");
        let (_, t2) = rotation.rotate(&t1).await.expect("rotate 应成功");
        let t2_hash = sha256_hex(&t2);
        // 整链吊销后再呈现 t1 → 无存活血缘（StaleLineage）
        rotation
            .revoke_chain(&sha256_hex(&t1))
            .await
            .expect("revoke_chain 应成功");

        let result = rotation.rotate(&t1).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "StaleLineage 在 Unauthorised 下仍应返回 TokenRevoked，实际: {:?}",
            result
        );
        assert_eq!(query_revoked(&pool, &t2_hash).await, 1, "链应保持吊销");
    }

    // ========================================================================
    // _chain 测试
    // ========================================================================

    /// `revoke_chain` 撤销给定 token 及其所有子代（沿 parent_token_hash 反向递归）。
    ///
    /// 构造链：t1 (parent=None) ← t2 (parent=t1) ← t3 (parent=t2)
    /// （t3 是最新，t1 是最老）
    ///
    /// 调用 `revoke_chain(SHA-256(t1))` → 应撤销 t1 及其所有子代（t2, t3）
    ///
    /// 断言：t1/t2/t3 的 revoked 字段全为 1
    ///
    /// **命名说明**：原测试名 `revoke_chain_revokes_all_parent_tokens`
    /// 与实际语义有歧义——实际撤销的是 t1 及其所有"子代"（descendant），
    /// 而非"父代"（parent）。此处沿用原命名以保持一致，
    /// 但语义以 doc comment 为准。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_chain_revokes_all_parent_tokens() {
        let pool = setup_db().await;

        // 构造链 t1 ← t2 ← t3（t3 最新）
        let t1_hash = sha256_hex("t1");
        let t2_hash = sha256_hex("t2");
        let t3_hash = sha256_hex("t3");
        insert_refresh_token(&pool, &t1_hash, None, 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t2_hash, Some(&t1_hash), 1, 0, 1, 9999, 0).await;
        insert_refresh_token(&pool, &t3_hash, Some(&t2_hash), 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // revoke_chain(t1_hash) → t1 + 所有子代（t2, t3）全 revoked
        rotation
            .revoke_chain(&t1_hash)
            .await
            .expect("revoke_chain 应成功");

        assert_eq!(query_revoked(&pool, &t1_hash).await, 1, "t1 应 revoked");
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应 revoked（子代）"
        );
        assert_eq!(
            query_revoked(&pool, &t3_hash).await,
            1,
            "t3 应 revoked（孙代）"
        );
    }

    // ========================================================================
    // with reuse detection 测试
    // ========================================================================

    /// `rotate` 检测到 old_token 重用时返回 `InvalidToken` 并吊销整个链。
    ///
    /// 流程：
    /// 1. 预先 INSERT t1 record（revoked=0）
    /// 2. `rotate("t1")` → 得到 t2（new_refresh），t1 revoked=1
    /// 3. `rotate("t1")` again（重用 t1） → 应返回 `GarrisonError::InvalidToken`
    /// 4. 断言 t1 的 revoked=1（已 revoked）
    /// 5. 断言 t2 的 revoked=1（链被吊销）
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_with_reuse_detection_revokes_chain() {
        let pool = setup_db().await;

        let t1_token = "t1_token_value";
        let t1_hash = sha256_hex(t1_token);
        insert_refresh_token(&pool, &t1_hash, None, 1, 0, 1, 9999, 0).await;

        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // 第一次 rotate：t1 → t2（成功）
        let (_, t2_refresh) = rotation
            .rotate(t1_token)
            .await
            .expect("第一次 rotate 应成功");
        let t2_hash = sha256_hex(&t2_refresh);

        // 第二次 rotate（重用 t1）：应返回 TokenRevoked（RFC 7009 Token Revocation）
        let result = rotation.rotate(t1_token).await;
        assert!(
            matches!(result, Err(GarrisonError::TokenRevoked(_))),
            "重用已消费的 refresh token 应返回 TokenRevoked，实际: {:?}",
            result
        );

        // 断言 t1 和 t2 的链全被吊销
        assert_eq!(
            query_revoked(&pool, &t1_hash).await,
            1,
            "t1 应 revoked（重用检测后）"
        );
        assert_eq!(
            query_revoked(&pool, &t2_hash).await,
            1,
            "t2 应 revoked（链被吊销）"
        );
    }

    // ========================================================================
    // 方法测试
    // ========================================================================

    /// →Green: `issue` 后 `validate` 返回 Some，字段匹配。
    ///
    /// 流程：
    /// 1. `issue(client_id, user_id, scopes, username, login_id, tenant_id, ttl)`
    /// 2. `validate(refresh_token)` 返回 Some(record)
    /// 3. 断言 record 字段与传入参数匹配
    /// 4. 断言 parent_token_hash 为 None（首次签发）
    /// 5. 断言 revoked 为 false
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_creates_record_with_correct_fields() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(2)));

        let scopes = vec!["read".to_string(), "write".to_string()];
        let refresh_token = rotation
            .issue(
                "client_abc",
                Some(42),
                &scopes,
                Some("alice"),
                42,
                5,
                86400 * 7,
            )
            .await
            .expect("issue 应成功");

        let record = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功")
            .expect("record 应存在");

        assert_eq!(
            record.parent_token_hash, None,
            "首次签发 parent_token_hash 应为 None"
        );
        assert!(!record.revoked, "新签发的 token 应未 revoked");
        assert_eq!(record.tenant_id, 5);
        assert_eq!(record.key_version, 2);
        assert_eq!(record.login_id, 42);
        assert_eq!(record.client_id, Some("client_abc".to_string()));
        assert_eq!(record.scopes, Some("read write".to_string()));
        assert_eq!(record.username, Some("alice".to_string()));
        assert_eq!(record.user_id, Some(42));
    }

    /// →Green: 空 scopes 列表时 scopes 字段为 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_with_empty_scopes_stores_none() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue(
                "client_xyz",
                None, // client_credentials 无 user_id
                &[],  // 空 scopes
                None,
                0,
                0,
                3600,
            )
            .await
            .expect("issue 应成功");

        let record = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功")
            .expect("record 应存在");

        assert_eq!(record.scopes, None, "空 scopes 列表应存储为 None");
        assert_eq!(record.user_id, None, "client_credentials 无 user_id");
        assert_eq!(record.username, None);
    }

    // ========================================================================
    // 方法测试
    // ========================================================================

    /// →Green: 有效 token 返回 Some。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_some_for_valid_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue("client_1", Some(1), &["read".to_string()], None, 1, 0, 3600)
            .await
            .expect("issue 应成功");

        let result = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功");
        assert!(result.is_some(), "有效 token 应返回 Some");
    }

    /// →Green: 已 revoked token 返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_none_for_revoked_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let refresh_token = rotation
            .issue("client_1", Some(1), &["read".to_string()], None, 1, 0, 3600)
            .await
            .expect("issue 应成功");

        // rotate 后旧 token 应被 revoked，validate 返回 None
        let _ = rotation
            .rotate(&refresh_token)
            .await
            .expect("rotate 应成功");
        let result = rotation
            .validate(&refresh_token)
            .await
            .expect("validate 应成功");
        assert!(result.is_none(), "已 revoked token 应返回 None");
    }

    /// →Green: 不存在 token 返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn validate_returns_none_for_nonexistent_token() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let result = rotation
            .validate("nonexistent_token_12345")
            .await
            .expect("validate 应成功");
        assert!(result.is_none(), "不存在的 token 应返回 None");
    }

    // ========================================================================
    // 继承 OAuth2 字段测试
    // ========================================================================

    /// →Green: `issue` 带 OAuth2 字段后 `rotate`，新记录继承这些字段。
    ///
    /// 流程：
    /// 1. `issue` 带 client_id / scopes / username / user_id
    /// 2. `rotate(old_token)` 得到 new_refresh
    /// 3. `validate(new_refresh)` 返回 Some
    /// 4. 断言新记录继承 client_id / scopes / username / user_id
    /// 5. 断言新记录 parent_token_hash 指向旧记录 token_hash
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_inherits_oauth2_fields() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let scopes = vec!["admin".to_string(), "read".to_string()];
        let old_token = rotation
            .issue(
                "client_inherit",
                Some(99),
                &scopes,
                Some("bob"),
                99,
                3,
                86400,
            )
            .await
            .expect("issue 应成功");

        let old_hash = sha256_hex(&old_token);

        // rotate
        let (_, new_refresh) = rotation.rotate(&old_token).await.expect("rotate 应成功");

        // validate 新 token
        let new_record = rotation
            .validate(&new_refresh)
            .await
            .expect("validate 应成功")
            .expect("新 token 应存在");

        // 断言继承 OAuth2 字段
        assert_eq!(new_record.client_id, Some("client_inherit".to_string()));
        assert_eq!(new_record.scopes, Some("admin read".to_string()));
        assert_eq!(new_record.username, Some("bob".to_string()));
        assert_eq!(new_record.user_id, Some(99));
        // 断言 hash chain
        assert_eq!(
            new_record.parent_token_hash,
            Some(old_hash),
            "新记录 parent_token_hash 应指向旧记录 token_hash"
        );
        // 旧 token 应 revoked
        let old_record = rotation
            .validate(&old_token)
            .await
            .expect("validate 应成功");
        assert!(old_record.is_none(), "旧 token 应已 revoked");
    }

    /// OAuth2 字段为 NULL 的记录 rotate 后，新记录字段也为 None。
    ///
    /// JWT 模块签发的记录不含 OAuth2 字段（列为 NULL）；
    /// rotate 链式继承：新记录的 OAuth2 字段继承旧记录的 NULL。
    #[tokio::test(flavor = "multi_thread")]
    async fn rotate_old_record_with_null_new_fields_inherits_none() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        // INSERT 不含 OAuth2 字段（列为 NULL，如 JWT 模块签发的记录）
        let old_token = "rotation_source_token";
        let old_hash = sha256_hex(old_token);
        insert_refresh_token(&pool, &old_hash, None, 1, 0, 1, 9999, 0).await;

        // rotate
        let (_, new_refresh) = rotation.rotate(old_token).await.expect("rotate 应成功");

        // validate 新 token
        let new_record = rotation
            .validate(&new_refresh)
            .await
            .expect("validate 应成功")
            .expect("新 token 应存在");

        // 断言 OAuth2 字段为 None（继承自旧记录的 NULL）
        assert_eq!(
            new_record.client_id, None,
            "旧记录 client_id 为 NULL，新记录应继承 None"
        );
        assert_eq!(new_record.scopes, None);
        assert_eq!(new_record.username, None);
        assert_eq!(new_record.user_id, None);
    }

    // ========================================================================
    // cleanup_expired 测试
    // ========================================================================

    /// 查询 refresh_tokens 表中的记录总数。
    async fn count_records(pool: &DbPool) -> usize {
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS cnt FROM refresh_tokens",
            vec![],
        );
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("COUNT 应成功")
            .expect("应有结果");
        row.try_get::<i64>("", "cnt").unwrap() as usize
    }

    /// cleanup_expired 仅删除 revoked=1 且 expires_at < (now - 7天) 的记录。
    ///
    /// 场景覆盖：
    /// - revoked=1 且 expires_at 远超 grace period → 应被删除
    /// - revoked=0 且 expires_at 已过期 → 不应删除（审计价值）
    /// - revoked=1 但 expires_at 在 grace period 内 → 不应删除
    /// - revoked=0 且 expires_at 未过期 → 不应删除
    #[tokio::test(flavor = "multi_thread")]
    async fn cleanup_expired_deletes_only_revoked_and_expired() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let seven_days_ago = now - 7 * 86400;

        // 1. revoked=1, expires_at 远超 grace period（30 天前过期）→ 应删除
        insert_refresh_token(
            &pool,
            "hash_revoked_expired",
            None,
            1,
            0,
            1,
            seven_days_ago - 86400 * 23,
            1,
        )
        .await;
        // 2. revoked=0, expires_at 已过期（10 天前）→ 不应删除
        insert_refresh_token(
            &pool,
            "hash_active_expired",
            None,
            2,
            0,
            1,
            seven_days_ago - 86400 * 3,
            0,
        )
        .await;
        // 3. revoked=1, expires_at 在 grace period 内（3 天前过期）→ 不应删除
        insert_refresh_token(
            &pool,
            "hash_revoked_within_grace",
            None,
            3,
            0,
            1,
            seven_days_ago + 86400 * 4,
            1,
        )
        .await;
        // 4. revoked=0, expires_at 未过期（7 天后）→ 不应删除
        insert_refresh_token(
            &pool,
            "hash_active_valid",
            None,
            4,
            0,
            1,
            now + 86400 * 7,
            0,
        )
        .await;

        assert_eq!(count_records(&pool).await, 4, "cleanup 前应有 4 条记录");

        let deleted = rotation
            .cleanup_expired()
            .await
            .expect("cleanup_expired 应成功");
        assert_eq!(
            deleted, 1,
            "应仅删除 1 条记录（revoked=1 且 expires_at 超过 grace period）"
        );

        let remaining = count_records(&pool).await;
        assert_eq!(remaining, 3, "应剩余 3 条记录");

        // 验证被删除的是正确的记录
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT token_hash FROM refresh_tokens ORDER BY token_hash",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("SELECT 应成功");
        let hashes: Vec<String> = rows
            .iter()
            .map(|r| r.try_get::<String>("", "token_hash").unwrap())
            .collect();
        assert!(
            hashes.contains(&"hash_active_expired".to_string()),
            "未撤销的过期记录应保留"
        );
        assert!(
            hashes.contains(&"hash_revoked_within_grace".to_string()),
            "grace period 内的撤销记录应保留"
        );
        assert!(
            hashes.contains(&"hash_active_valid".to_string()),
            "有效记录应保留"
        );
        assert!(
            !hashes.contains(&"hash_revoked_expired".to_string()),
            "已撤销且过期超过 grace period 的记录应被删除"
        );
    }

    /// cleanup_expired 在无匹配记录时返回 0。
    #[tokio::test(flavor = "multi_thread")]
    async fn cleanup_expired_returns_zero_when_nothing_to_clean() {
        let pool = setup_db().await;
        let jwt_handler = Arc::new(JwtHandler::new("test_secret_that_is_at_least_32_bytes"));
        let rotation =
            RefreshTokenRotation::new(pool.clone(), jwt_handler, Arc::new(RwLock::new(1)));

        let deleted = rotation
            .cleanup_expired()
            .await
            .expect("cleanup_expired 应成功");
        assert_eq!(deleted, 0, "空表应返回 0");
    }
}
