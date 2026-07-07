//! 协议层集成测试入口——JWT / OAuth2 / SSO / Sign / APIKey / Temp 协议端到端验证。

#[path = "protocol/apikey_edge_cases.rs"]
mod apikey_edge_cases;
#[path = "protocol/jwt_edge_cases.rs"]
mod jwt_edge_cases;
#[path = "protocol/jwt_integration.rs"]
mod jwt_integration;
#[path = "protocol/oauth2_edge_cases.rs"]
mod oauth2_edge_cases;
#[path = "protocol/oauth2_integration.rs"]
mod oauth2_integration;
#[path = "protocol/sign_edge_cases.rs"]
mod sign_edge_cases;
#[path = "protocol/sso_edge_cases.rs"]
mod sso_edge_cases;
#[path = "protocol/sso_integration.rs"]
mod sso_integration;
#[path = "protocol/temp_edge_cases.rs"]
mod temp_edge_cases;
