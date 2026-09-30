// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! restricted 会话：找回密码恢复会话的最小授权约束。
//!
//! 标记写入 Token-Session 的 `attrs`（`GarrisonSession::set`，键
//! [`RESTRICTED_ATTR_KEY`]），端点约束检查读同一键：标记存在时仅
//! [`ENDPOINT_PASSWORD_CHANGE`]（改密端点）可达，其余端点一律
//! [`GarrisonError::NotPermission`]（HTTP 403）。
//!
//! 密码改写成功后由调用方清除标记（[`RestrictedSessionGuard::clear`]）；
//! 会话 TTL 到期时标记随 Token-Session 自然失效。

use crate::error::{GarrisonError, GarrisonResult};
use crate::session::GarrisonSession;
use std::sync::Arc;

/// restricted 标记的 Token-Session attrs 键。
pub const RESTRICTED_ATTR_KEY: &str = "pwdreset_restricted";

/// restricted 会话唯一可达的端点标识（改密端点）。
///
/// **已知残余风险（安全审查记录，显性声明）**：`check_endpoint` 是约束的
/// 唯一原语，其生效依赖宿主在每个非改密端点的鉴权路径显式调用——框架未
/// 提供自动执行的 web middleware（遗漏接线 = fail-open）。集成方须：
/// ①在共用鉴权咽喉点统一接入 `check_endpoint`；或 ②以本模块的 axum
/// middleware 先例（web/axum/waf.rs 模式）自行封装。该缺口的自动化强制
/// 执行层留待后续 change 承接。
pub const ENDPOINT_PASSWORD_CHANGE: &str = "password_change";

/// restricted 标记值：记录标记来源（找回密码流程），值为常量，仅作存在性判定。
const RESTRICTED_ATTR_VALUE: &str = "password_reset";

/// restricted 会话 guard：授权凭据操作时写入标记，`clear` 消费时移除。
///
/// 持 `Arc<GarrisonSession>` 引用；`clear` 消费 `self`，
/// RAII 语义上「标记生命周期 = guard 生命周期」由流程编排保证。
pub struct RestrictedSessionGuard {
    session: Arc<GarrisonSession>,
    token: String,
}

impl std::fmt::Debug for RestrictedSessionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // token 为敏感凭证：Debug 输出掩码（与 authflow AuthResult 同惯例）
        f.debug_struct("RestrictedSessionGuard")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl RestrictedSessionGuard {
    /// 在 token 会话上写入 restricted 标记（授权凭据操作）。
    ///
    /// # 错误
    /// - token 会话不存在：[`GarrisonError::InvalidToken`]
    pub async fn grant(session: Arc<GarrisonSession>, token: &str) -> GarrisonResult<Self> {
        session
            .set(token, RESTRICTED_ATTR_KEY, RESTRICTED_ATTR_VALUE)
            .await?;
        Ok(Self {
            session,
            token: token.to_string(),
        })
    }

    /// 校验 token 会话对端点的可达性。
    ///
    /// - 无 restricted 标记：非 restricted 会话，所有端点按既有权限体系放行（`Ok(())`）。
    /// - 有标记且 `endpoint == ENDPOINT_PASSWORD_CHANGE`：放行。
    /// - 有标记且端点不同：[`GarrisonError::NotPermission`]（HTTP 403）。
    pub async fn check_endpoint(
        session: &GarrisonSession,
        token: &str,
        endpoint: &str,
    ) -> GarrisonResult<()> {
        let restricted = session.get(token, RESTRICTED_ATTR_KEY).await?;
        match restricted {
            None => Ok(()),
            Some(_) if endpoint == ENDPOINT_PASSWORD_CHANGE => Ok(()),
            Some(_) => Err(GarrisonError::NotPermission(format!(
                "pwdreset-restricted-endpoint-denied::{endpoint}"
            ))),
        }
    }

    /// 清除 restricted 标记（宿主显式升级会话时调用，消费 guard）。
    ///
    /// 从 Token-Session 的 `attrs` 中移除标记键后原样保存（`dao.update`
    /// 保留原 TTL）。标记不存在（会话已过期/未打标）时幂等成功。
    pub async fn clear(self) -> GarrisonResult<()> {
        if let Some(mut ts) = self.session.get_token_session(&self.token).await? {
            if ts.attrs.remove(RESTRICTED_ATTR_KEY).is_some() {
                self.session.save_token_session(&self.token, &ts).await?;
            }
        }
        Ok(())
    }
}
