// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! API Key 示例模块。

#[cfg(feature = "protocol-apikey")]
pub mod apikey_management;
#[cfg(all(feature = "protocol-apikey", feature = "cache-memory"))]
pub mod apikey_namespace;
