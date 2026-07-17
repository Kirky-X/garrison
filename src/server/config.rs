//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::AuthServerConfig;

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            external_port: 8080,
            internal_port: 8081,
            external_rate_limit_per_ip: 100,
            rate_limit_max_entries: 100_000,
            rate_limit_trusted_proxies: Vec::new(),
            internal_api_key: String::new(),
        }
    }
}
