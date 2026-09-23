// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 第一方扫码登录协议模块（feature = "protocol-qrlogin"）。
//!
//! Web 端展示二维码 → 用户用已登录的 App 扫码确认 → Web 端获得会话的跨设备异步认证。
//! 核心为**两票分离**状态机：qr_ticket（Web 端持有，编码进二维码）与 confirm_token
//! （App 端持有，扫码后颁发）——扫码 ≠ 确认，状态迁移只发生在服务端。
//!
//! ## 状态机
//!
//! ```text
//! Pending --scan--> Scanned --confirm--> Confirmed --poll(兑换)--> Consumed(终态)
//!    |                  |
//!    +-- TTL 到期 --> Expired（key 不存在表达，不落盘）
//! 任意非终态 <-- cancel
//! ```
//!
//! ## Key 命名空间
//!
//! - `garrison:qrlogin:session:<qr_id>`：会话 JSON，TTL = `QrLoginConfig::session_ttl_secs`
//! - `garrison:qrlogin:confirm:<confirm_token>`：qr_id，TTL = `QrLoginConfig::confirm_ttl_secs`
//!
//! 与 session/sign/sso/apikey/temp 命名空间隔离。
//!
//! ## 会话签发
//!
//! 本模块只管理票据状态机；兑换出的会话通过 [`QrLoginSessionIssuer`] 端口
//! （DIP）由调用方实现（server 层提供基于 Stp 的默认实现），协议层不依赖 stp/server。
//!
//! ## 安全语义与固有风险
//!
//! - **双票兑换**：qr_id 编码在公开可见的二维码票据（`t=` 参数）中，仅凭 qr_id
//!   可被肩窥/截图者抢先兑换；`bind_token` 作为第二票仅在 create 响应中下发给
//!   Web 端本人，poll 出示双票方可兑换。**二维码展示环境需可信**（投影/直播/
//!   共享屏幕场景等同公开票据）。
//! - **login CSRF（固有面）**：任意已登录 App 用户可扫他人屏幕上的二维码并
//!   确认，使受害者浏览器登录进攻击者账号。缓解：scan 响应向 App 端下发待登录
//!   端脱敏摘要（设备标签 + 创建时间）供扫码者核对；不核对的确认即可能被利用。
//! - **确认者绑定**：`confirm` 强制确认者身份与扫码者一致（服务端锁定，
//!   不信任请求体）；confirm_token 一次性且 TTL 短（默认 60s）。

pub mod issuer;

mod service;

#[cfg(test)]
mod tests;

use std::sync::Arc;

pub use issuer::QrLoginSessionIssuer;

use serde::{Deserialize, Serialize};

// ============================================================================
// QrLoginStatus：会话状态（落盘枚举）
// ============================================================================

/// 扫码登录会话状态（持久化枚举）。
///
/// `Expired` / `Consumed` 不落盘：分别由会话 key 的 TTL 过期（get 返回 None）
/// 与兑换后的 `get_and_delete`（key 已删）表达。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QrLoginStatus {
    /// 已创建，待扫码。
    Pending,
    /// 已扫码，待 App 确认。
    Scanned,
    /// App 已确认，待 Web 端兑换会话。
    Confirmed,
    /// App 主动取消（终态）。
    Cancelled,
}

// ============================================================================
// QrLoginWebContext：待登录端上下文
// ============================================================================

/// 待登录端（Web 浏览器）上下文，create 时采集。
///
/// 用于 App 确认页展示脱敏摘要（Quishing 防御：用户可核对发起登录的设备）；
/// 原始 IP / UA 仅落盘供审计，不下发给 App 端。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QrLoginWebContext {
    /// 客户端 IP（来自中间件解析）。
    pub ip: Option<String>,
    /// 客户端 User-Agent。
    pub user_agent: Option<String>,
    /// 会话创建时间（Unix 毫秒）。
    #[serde(default)]
    pub created_at_ms: i64,
}

// ============================================================================
// QrLoginSessionData：会话存储 JSON
// ============================================================================

/// 扫码登录会话数据（`garrison:qrlogin:session:<qr_id>` 的 JSON 载荷）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrLoginSessionData {
    /// 会话随机标识（64 hex，即 qr_ticket 的 random_part）。
    pub qr_id: String,
    /// 当前状态。
    pub status: QrLoginStatus,
    /// 租户 ID（默认 0；向前兼容多租户部署）。
    #[serde(default)]
    pub tenant_id: i64,
    /// 确认者 login_id（scan 时锁定，兑换时以此为准，不信任请求体）。
    #[serde(default)]
    pub app_login_id: Option<String>,
    /// confirm_token 的 SHA-256 hex 摘要（不落明文，DAO 泄露不可反推）。
    #[serde(default)]
    pub confirm_token_hash: Option<String>,
    /// 待登录端上下文。
    pub web: QrLoginWebContext,
}

// ============================================================================
// QrLoginScanView：scan 响应视图（脱敏摘要）
// ============================================================================

/// scan 成功后返回给 App 端的视图。
///
/// 含 confirm_token（一次性确认凭据）与待登录端**脱敏摘要**：
/// 设备标签（UA 解析短标签）+ 创建时间，不下发原始 IP / 完整 UA。
#[derive(Debug, Clone, Serialize)]
pub struct QrLoginScanView {
    /// 一次性确认凭据（confirm 时出示，TTL = confirm_ttl_secs）。
    pub confirm_token: String,
    /// 待登录端设备标签（UA 关键字解析，如 "Chrome"；解析失败为 "Unknown device"）。
    pub web_device_label: String,
    /// 待登录端会话创建时间（Unix 毫秒）。
    pub web_created_at_ms: i64,
    /// confirm_token 剩余有效期（秒，等于配置值）。
    pub expires_in_secs: u64,
}

// ============================================================================
// CreatedQrLogin：create 响应
// ============================================================================

/// create 成功返回给 Web 端的扫码登录创建结果。
#[derive(Debug, Clone, Serialize)]
pub struct CreatedQrLogin {
    /// 会话随机标识（Web 端轮询时出示；二维码仅编码签名票据，不含本值）。
    pub qr_id: String,
    /// Web 端轮询第二票（与 qr_id 绑定的一次性凭证）。
    ///
    /// qr_id 编码在公开展示的二维码票据中，仅凭 qr_id 即可抢先兑换会话；
    /// poll 必须同时出示本凭证（仅在 create 响应中下发给 Web 端本人），
    /// 肩窥/截图二维码者因拿不到 bind_token 而无法劫持兑换。
    pub bind_token: String,
    /// 二维码内容（URL，App 扫码后向 scan 端点提交其中的 `t` 参数票据）。
    pub qr_content: String,
    /// 二维码有效期（秒，等于配置的 session_ttl_secs）。
    pub expires_in_secs: u64,
}

// ============================================================================
// QrLoginAction / QrLoginPollOutcome：确认动作与轮询结果
// ============================================================================

/// App 端确认动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrLoginAction {
    /// 确认登录。
    Confirm,
    /// 取消登录。
    Cancel,
}

/// poll 结果。
///
/// 不派生 `Serialize`：`Confirmed` 分支携带 login_id，禁止原样序列化给匿名
/// 轮询方——HTTP 层须将其转换为服务端签发的 token 后再响应。
#[derive(Debug, Clone, PartialEq)]
pub enum QrLoginPollOutcome {
    /// 待扫码。
    Pending,
    /// 已扫码待确认。
    Scanned,
    /// 已确认；携带确认者 login_id 与租户 ID（仅在服务端内部可见）。
    Confirmed {
        /// 确认者 login_id。
        login_id: String,
        /// 租户 ID。
        tenant_id: i64,
    },
    /// 已取消。
    Cancelled,
    /// 不存在或已过期。
    Expired,
}

// ============================================================================
// QrLoginConfig：配置（构造后不可变）
// ============================================================================

/// 扫码登录配置。
///
/// 经 [`QrLoginService::with_config`] 注入，构造后不可变。
/// `Default` 实现见 service.rs（mod.rs 不留 impl 块）。
#[derive(Debug, Clone)]
pub struct QrLoginConfig {
    /// 二维码/会话有效期（秒），默认 120。
    pub session_ttl_secs: u64,
    /// confirm_token 有效期（秒），默认 60。
    pub confirm_ttl_secs: u64,
    /// qr_content 允许的域名白名单（精确匹配 host，含端口）。
    ///
    /// `None` 表示不校验域名（scan 阶段跳过）；生产部署建议配置以压制
    /// Quishing（二维码替换钓鱼）。
    pub allowed_domains: Option<Vec<String>>,
}

// ============================================================================
// QrLoginService：扫码登录服务（impl 见 service.rs，mod.rs 不留 impl 块）
// ============================================================================

/// 扫码登录服务。
///
/// 持有 `Arc<dyn GarrisonDao>`（票据与状态存储）与 HMAC secret（qr_ticket 签名）。
/// 全部方法见 `service.rs` 实现。
pub struct QrLoginService {
    /// 数据访问抽象（票据与会话状态存储）。
    dao: Arc<dyn crate::dao::GarrisonDao>,
    /// HMAC-SHA256 签名密钥（qr_ticket 防伪造）。
    secret: String,
    /// 配置（构造后不可变）。
    config: QrLoginConfig,
    /// 可选监听器管理器（`listener` feature）：create/scan/confirm/cancel 广播事件。
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<crate::listener::GarrisonListenerManager>>,
}
