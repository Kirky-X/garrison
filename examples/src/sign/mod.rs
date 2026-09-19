// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 签名协议示例模块。

#[cfg(feature = "protocol-invitation")]
pub mod invitation_credential;
#[cfg(feature = "protocol-sign")]
pub mod sign_protocol;
#[cfg(feature = "secure-sign")]
pub mod sign_utils;
#[cfg(feature = "protocol-temp")]
pub mod temp_credential;
