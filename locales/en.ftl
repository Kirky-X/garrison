# Bulwark exception message English translations
# Per spec exception-i18n and PRD 0.3.0 internationalization

not-login = Not logged in: {$detail}
not-permission = Permission denied: {$detail}
not-role = Role denied: {$detail}
invalid-token = Invalid token: {$detail}
expired-token = Token expired: {$detail}
dao = DAO error: {$detail}
config = Configuration error: {$detail}
internal = Internal error: {$detail}
session = Session error: {$detail}
annotation = Annotation error: {$detail}
context = Context error: {$detail}
oauth2 = OAuth2 error: {$detail}
network = Network error: {$detail}
invalid-param = Invalid parameter: {$detail}
not-implemented = Not implemented: {$detail}
exception = Business exception[{$code}]: {$detail}

# 0.6.1 new error variants (per spec error-exceptions R-error-001~003)
disable-service = Account disabled: service={$service}, until={$until}
not-safe = Second factor authentication required: {$reason}
invalid-state-transition = Invalid state transition: {$from} -> {$to}

# SMS verification code progressive rate limiting exceptions (Phase 4 D4)
sms-rate-limit-exceeded = SMS rate limit exceeded: {$window} window
sms-verify-max-attempts = SMS verification max attempts exceeded
sms-code-not-found = SMS verification code not found
sms-channel-recycled = SMS channel recycled

# ============================================================================
# Social login exception messages (0.6.0, per T021)
# ============================================================================

# --- WeChat QR code login (wechat) ---
wechat-token-request-failed = WeChat token request failed: {$detail}
wechat-token-response-parse-failed = WeChat token response parse failed: {$detail}
wechat-error-response = WeChat error {$code}: {$message}
wechat-response-missing-openid = WeChat response missing openid field
wechat-userinfo-request-failed = WeChat userinfo request failed: {$detail}
wechat-userinfo-response-parse-failed = WeChat userinfo response parse failed: {$detail}
wechat-userinfo-response-missing-openid = WeChat userinfo response missing openid field

# --- WeChat Mini App (wechat mini-app) ---
wechat-mini-app-get-authorization-url-not-supported = WechatMiniAppProvider does not support get_authorization_url (mini app uses wx.login() to get js_code directly)
wechat-mini-app-jscode2session-request-failed = WeChat mini-app jscode2session request failed: {$detail}
wechat-mini-app-jscode2session-response-parse-failed = WeChat mini-app jscode2session response parse failed: {$detail}
wechat-mini-app-error-response = WeChat mini-app error {$code}: {$message}
wechat-mini-app-jscode2session-response-missing-openid = WeChat mini-app jscode2session response missing openid field

# --- Alipay authorization login (alipay) ---
alipay-rsa-key-parse-failed = Alipay RSA private key parse failed: {$detail}
alipay-token-request-failed = Alipay token request failed: {$detail}
alipay-token-response-parse-failed = Alipay token response parse failed: {$detail}
alipay-error-response = Alipay error {$code}: {$message}
alipay-response-missing-user-id = Alipay response missing user_id field
alipay-user-info-request-failed = Alipay user info request failed: {$detail}
alipay-user-info-response-parse-failed = Alipay user info response parse failed: {$detail}
alipay-response-missing-user-info-share-response = Alipay response missing alipay_user_info_share_response field

# --- Keycloak OIDC RP (keycloak) ---
keycloak-http-client-build-failed = Failed to build HTTP client: {$detail}
keycloak-discovery-request-failed = Discovery request failed: {$detail}
keycloak-discovery-status-not-2xx = Discovery response status not 2xx: {$detail}
keycloak-discovery-response-parse-failed = Discovery response parse failed: {$detail}
keycloak-jwks-request-failed = JWKS request failed: {$detail}
keycloak-jwks-status-not-2xx = JWKS response status not 2xx: {$detail}
keycloak-jwks-response-parse-failed = JWKS response parse failed: {$detail}
keycloak-id-token-header-parse-failed = id_token header parse failed: {$detail}
keycloak-id-token-header-missing-kid = id_token header missing kid field
keycloak-jwks-key-not-found = JWKS key not found for kid={$kid}
keycloak-rsa-public-key-build-failed = Failed to build RSA public key: {$detail}
keycloak-token-expired = Token expired
keycloak-id-token-verify-failed = id_token verification failed: {$detail}
keycloak-code-empty = code must not be empty
keycloak-public-client-requires-pkce = Public client (client_secret=None) must call with_pkce to set PKCE verifier
keycloak-exchange-code-request-failed = exchange_code request failed: {$detail}
keycloak-exchange-code-status-not-2xx = exchange_code response status not 2xx: {$detail}
keycloak-exchange-code-response-parse-failed = exchange_code response parse failed: {$detail}
