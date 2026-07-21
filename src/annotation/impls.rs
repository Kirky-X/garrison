//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `Annotation` / `AnnotationMode` 的 Display / FromStr / 内联方法实现。

use super::{Annotation, AnnotationMode};
use crate::error::GarrisonError;

impl std::fmt::Display for AnnotationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnotationMode::And => write!(f, "AND"),
            AnnotationMode::Or => write!(f, "OR"),
        }
    }
}

impl Annotation {
    /// 获取注解的字符串名称。
    ///
    /// 返回对应 注解的字符串标识（用于 router 中间件配置与日志记录）。
    pub fn name(&self) -> &'static str {
        match self {
            Annotation::CheckLogin => "CheckLogin",
            Annotation::CheckPermission(_) => "CheckPermission",
            Annotation::CheckRole(_) => "CheckRole",
            Annotation::CheckSafe => "CheckSafe",
            Annotation::CheckDisable => "CheckDisable",
            Annotation::CheckOr => "CheckOr",
            Annotation::CheckAnd => "CheckAnd",
            Annotation::CheckNot => "CheckNot",
            Annotation::Ignore => "Ignore",
            Annotation::CheckBasicAuth => "CheckBasicAuth",
            Annotation::CheckDigestAuth => "CheckDigestAuth",
            Annotation::CheckSign => "CheckSign",
            Annotation::CheckApiKey { .. } => "CheckApiKey",
            Annotation::Mode(_) => "Mode",
            Annotation::CheckAccessToken => "CheckAccessToken",
            Annotation::CheckClientToken => "CheckClientToken",
        }
    }
}

impl std::fmt::Display for Annotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Annotation {
    type Err = GarrisonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CheckLogin" => Ok(Annotation::CheckLogin),
            "CheckSafe" => Ok(Annotation::CheckSafe),
            "CheckDisable" => Ok(Annotation::CheckDisable),
            "CheckOr" => Ok(Annotation::CheckOr),
            "CheckAnd" => Ok(Annotation::CheckAnd),
            "CheckNot" => Ok(Annotation::CheckNot),
            "Ignore" => Ok(Annotation::Ignore),
            "CheckBasicAuth" => Ok(Annotation::CheckBasicAuth),
            "CheckDigestAuth" => Ok(Annotation::CheckDigestAuth),
            "CheckSign" => Ok(Annotation::CheckSign),
            "CheckAccessToken" => Ok(Annotation::CheckAccessToken),
            "CheckClientToken" => Ok(Annotation::CheckClientToken),
            _ => Err(GarrisonError::InvalidParam(format!(
                "无法从字符串解析注解（含数据变体需显式构造）: {}",
                s
            ))),
        }
    }
}
