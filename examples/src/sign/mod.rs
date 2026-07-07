//! 签名协议示例模块。

#[cfg(feature = "protocol-sign")]
pub mod sign_protocol;
#[cfg(feature = "secure-sign")]
pub mod sign_utils;
#[cfg(feature = "protocol-temp")]
pub mod temp_credential;
