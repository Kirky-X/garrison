//! 跨模块集成测试入口——axum / login_password / tenant_isolation / strategy / refresh_token / plugin / keycloak / jwt_modes / annotation。

#[path = "common/mod.rs"]
mod common;

#[path = "integration/annotation.rs"]
mod annotation;
#[path = "integration/annotation_macros.rs"]
mod annotation_macros;
#[path = "integration/axum.rs"]
mod axum;
#[path = "integration/jwt_modes.rs"]
mod jwt_modes;
#[path = "integration/keycloak_oidc.rs"]
mod keycloak_oidc;
#[path = "integration/login_password.rs"]
mod login_password;
#[path = "integration/plugin_listener.rs"]
mod plugin_listener;
#[path = "integration/refresh_token.rs"]
mod refresh_token;
#[path = "integration/strategy_registry.rs"]
mod strategy_registry;
#[path = "integration/tenant_isolation.rs"]
mod tenant_isolation;
