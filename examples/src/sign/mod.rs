//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 签名协议示例模块。

#[cfg(feature = "protocol-sign")]
pub mod sign_protocol;
#[cfg(feature = "secure-sign")]
pub mod sign_utils;
#[cfg(feature = "protocol-temp")]
pub mod temp_credential;
