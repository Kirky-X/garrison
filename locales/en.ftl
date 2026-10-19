# Garrison exception message English translations
# Per spec exception-i18n and PRD 0.3.0 internationalization
#
# Structured error detail convention (see src/i18n.rs::parse_keyed_detail):
#   Caller writes `format!("some-key::{}", arg0)` or `format!("some-key::{}::{}", arg0, arg1)`.
#   `::` separates key from positional args; FTL template receives them as {$arg0}/{$arg1}.
#   Plain Chinese/English strings (no `::`) fall back to variant default key + {$detail}.

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
invalid-response = Invalid upstream response: {$detail}
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

# Gateway-level rate limiting (GarrisonError::RateLimited, R04 unified error model)
rate-limited = Rate limited

# Email verification code rate limiting exceptions (email-verification)
email-rate-limit-exceeded = Email rate limit exceeded: {$window} window
email-verify-max-attempts = Email verification max attempts exceeded
email-code-not-found = Email verification code not found
email-channel-recycled = Email channel recycled

# Credit metering insufficient (multi-tenant-credit-metering)
credit-insufficient = Credit insufficient: tenant={$tenant_id}, requested={$requested}, remaining={$remaining}

# 0.6.1 missing base keys (I18N-KEY-01 / I18N-KEY-02)
token-revoked = Token revoked: {$detail}
firewall-blocked = Firewall blocked: {$detail}

# Social login exception messages (0.6.0)

# WeChat QR code login (wechat)
wechat-token-request-failed = WeChat token request failed: {$detail}
wechat-token-response-parse-failed = WeChat token response parse failed: {$detail}
wechat-error-response = WeChat error {$code}: {$message}
wechat-response-missing-openid = WeChat response missing openid field
wechat-userinfo-request-failed = WeChat userinfo request failed: {$detail}
wechat-userinfo-response-parse-failed = WeChat userinfo response parse failed: {$detail}
wechat-userinfo-response-missing-openid = WeChat userinfo response missing openid field
wechat-redirect-uri-must-be-https = WeChat redirect_uri must be an https URL

# First-party QR code login (qrlogin)
qrlogin-secret-empty = QR login HMAC secret must not be empty
qrlogin-secret-too-short = QR login HMAC secret must be at least 32 bytes
qrlogin-session-not-found = QR login session not found
qrlogin-session-expired = QR login session has expired
qrlogin-invalid-ticket = QR login ticket signature is invalid
qrlogin-already-scanned = QR login session has already been scanned
qrlogin-not-scanned = QR login session has not been scanned yet
qrlogin-already-consumed = QR login session has already been consumed
qrlogin-cancelled = QR login session has been cancelled
qrlogin-confirm-token-invalid = QR login confirm token is invalid or has expired
qrlogin-domain-not-allowed = QR login ticket domain is not allowed
qrlogin-issuer-failed = QR login session issuance failed: {$detail}
qrlogin-app-unauthorized = QR login requires a valid app session token
qrlogin-action-invalid = action must be "confirm" or "cancel"

# WeChat Mini App (wechat mini-app)
wechat-mini-app-get-authorization-url-not-supported = WechatMiniAppProvider does not support get_authorization_url (mini app uses wx.login() to get js_code directly)
wechat-mini-app-jscode2session-request-failed = WeChat mini-app jscode2session request failed: {$detail}
wechat-mini-app-jscode2session-response-parse-failed = WeChat mini-app jscode2session response parse failed: {$detail}
wechat-mini-app-error-response = WeChat mini-app error {$code}: {$message}
wechat-mini-app-jscode2session-response-missing-openid = WeChat mini-app jscode2session response missing openid field

# Alipay authorization login (alipay)
alipay-rsa-key-parse-failed = Alipay RSA private key parse failed: {$detail}
alipay-token-request-failed = Alipay token request failed: {$detail}
alipay-token-response-parse-failed = Alipay token response parse failed: {$detail}
alipay-error-response = Alipay error {$code}: {$message}
alipay-response-missing-user-id = Alipay response missing user_id field
alipay-user-info-request-failed = Alipay user info request failed: {$detail}
alipay-user-info-response-parse-failed = Alipay user info response parse failed: {$detail}
alipay-response-missing-user-info-share-response = Alipay response missing alipay_user_info_share_response field
alipay-http-client-build-failed = Alipay HTTP client build failed: {$detail}

# Keycloak OIDC RP (keycloak)
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

# Huawei Account Kit (huawei, sinnan custom provider)
huawei-token-request-failed = Huawei token request failed: {$detail}
huawei-token-response-parse-failed = Huawei token response parse failed: {$detail}
huawei-error-response = Huawei error response: {$detail}
huawei-token-response-missing-access-token = Huawei token response missing access_token field
huawei-get-user-info-failed-after-token-exchange = Huawei get_user_info failed after token exchange (code consumed, please re-authorize): {$detail}
huawei-userinfo-request-failed = Huawei userinfo request failed: {$detail}
huawei-userinfo-response-parse-failed = Huawei userinfo response parse failed: {$detail}
huawei-userinfo-business-error = Huawei userinfo business error: {$detail}
huawei-userinfo-response-missing-openID = Huawei userinfo response missing openID field

# DAO errors (i18n refactor)
dao-app-auth-method-create-insert = app_auth_method create insert failed: {$arg0}
dao-app-auth-method-create-session = app_auth_method create get session failed: {$arg0}
dao-app-auth-method-delete-delete = app_auth_method delete delete failed: {$arg0}
dao-app-auth-method-delete-session = app_auth_method delete get session failed: {$arg0}
dao-app-auth-method-find-by-id-query = app_auth_method find-by-id query failed: {$arg0}
dao-app-auth-method-find-by-user-id-query = app_auth_method find-by-user-id query failed: {$arg0}
dao-app-auth-method-list-connection = app_auth_method list get connection failed: {$arg0}
dao-app-auth-method-list-query = app_auth_method list query failed: {$arg0}
dao-app-auth-method-list-session = app_auth_method list get session failed: {$arg0}
dao-app-auth-method-row-parse-create-time = app_auth_method row parse failed (create_time): {$arg0}
dao-app-auth-method-row-parse-external-id = app_auth_method row parse failed (external_id): {$arg0}
dao-app-auth-method-row-parse-id = app_auth_method row parse failed (id): {$arg0}
dao-app-auth-method-row-parse-metadata = app_auth_method row parse failed (metadata): {$arg0}
dao-app-auth-method-row-parse-method-type = app_auth_method row parse failed (method_type): {$arg0}
dao-app-auth-method-row-parse-tenant-id = app_auth_method row parse failed (tenant_id): {$arg0}
dao-app-auth-method-row-parse-user-id = app_auth_method row parse failed (user_id): {$arg0}
dao-app-login-log-create-connection = app_login_log create get connection failed: {$arg0}
dao-app-login-log-create-insert = app_login_log create insert failed: {$arg0}
dao-app-login-log-create-session = app_login_log create get session failed: {$arg0}
dao-app-login-log-find-by-id-query = app_login_log find-by-id query failed: {$arg0}
dao-app-login-log-find-by-id-session = app_login_log find-by-id get session failed: {$arg0}
dao-app-login-log-find-by-user-id-query = app_login_log find-by-user-id query failed: {$arg0}
dao-app-login-log-list-connection = app_login_log list get connection failed: {$arg0}
dao-app-login-log-list-query = app_login_log list query failed: {$arg0}
dao-app-login-log-list-session = app_login_log list get session failed: {$arg0}
dao-app-login-log-row-parse-action = app_login_log row parse failed (action): {$arg0}
dao-app-login-log-row-parse-create-time = app_login_log row parse failed (create_time): {$arg0}
dao-app-login-log-row-parse-device-id = app_login_log row parse failed (device_id): {$arg0}
dao-app-login-log-row-parse-fail-reason = app_login_log row parse failed (fail_reason): {$arg0}
dao-app-login-log-row-parse-id = app_login_log row parse failed (id): {$arg0}
dao-app-login-log-row-parse-ip = app_login_log row parse failed (ip): {$arg0}
dao-app-login-log-row-parse-tenant-id = app_login_log row parse failed (tenant_id): {$arg0}
dao-app-login-log-row-parse-user-id = app_login_log row parse failed (user_id): {$arg0}
dao-app-permission-create-connection = app_permission create get connection failed: {$arg0}
dao-app-permission-create-insert = app_permission create insert failed: {$arg0}
dao-app-permission-create-session = app_permission create get session failed: {$arg0}
dao-app-permission-delete-connection = app_permission delete get connection failed: {$arg0}
dao-app-permission-delete-delete = app_permission delete delete failed: {$arg0}
dao-app-permission-delete-session = app_permission delete get session failed: {$arg0}
dao-app-permission-find-by-code-query = app_permission find-by-code query failed: {$arg0}
dao-app-permission-find-by-id-query = app_permission find-by-id query failed: {$arg0}
dao-app-permission-list-connection = app_permission list get connection failed: {$arg0}
dao-app-permission-list-query = app_permission list query failed: {$arg0}
dao-app-permission-list-session = app_permission list get session failed: {$arg0}
dao-app-permission-row-parse-action = app_permission row parse failed (action): {$arg0}
dao-app-permission-row-parse-code = app_permission row parse failed (code): {$arg0}
dao-app-permission-row-parse-created-at = app_permission row parse failed (created_at): {$arg0}
dao-app-permission-row-parse-id = app_permission row parse failed (id): {$arg0}
dao-app-permission-row-parse-name = app_permission row parse failed (name): {$arg0}
dao-app-permission-row-parse-resource-type = app_permission row parse failed (resource_type): {$arg0}
dao-app-permission-row-parse-updated-at = app_permission row parse failed (updated_at): {$arg0}
dao-app-permission-update-connection = app_permission update get connection failed: {$arg0}
dao-app-permission-update-session = app_permission update get session failed: {$arg0}
dao-app-permission-update-update = app_permission update update failed: {$arg0}
dao-app-role-create-connection = app_role create get connection failed: {$arg0}
dao-app-role-create-insert = app_role create insert failed: {$arg0}
dao-app-role-create-session = app_role create get session failed: {$arg0}
dao-app-role-delete-connection = app_role delete get connection failed: {$arg0}
dao-app-role-delete-delete = app_role delete delete failed: {$arg0}
dao-app-role-delete-session = app_role delete get session failed: {$arg0}
dao-app-role-find-by-code-connection = app_role find-by-code get connection failed: {$arg0}
dao-app-role-find-by-code-query = app_role find-by-code query failed: {$arg0}
dao-app-role-find-by-code-session = app_role find-by-code get session failed: {$arg0}
dao-app-role-find-by-id-connection = app_role find-by-id get connection failed: {$arg0}
dao-app-role-find-by-id-query = app_role find-by-id query failed: {$arg0}
dao-app-role-find-by-id-session = app_role find-by-id get session failed: {$arg0}
dao-app-role-list-connection = app_role list get connection failed: {$arg0}
dao-app-role-list-query = app_role list query failed: {$arg0}
dao-app-role-list-session = app_role list get session failed: {$arg0}
dao-app-role-permission-assign-insert = app_role_permission assign insert failed: {$arg0}
dao-app-role-permission-list-query = app_role_permission list query failed: {$arg0}
dao-app-role-permission-list-session = app_role_permission list get session failed: {$arg0}
dao-app-role-permission-revoke-delete = app_role_permission revoke delete failed: {$arg0}
dao-app-role-permission-row-parse-role-id = app_role_permission row parse failed (role_id): {$arg0}
dao-app-role-permission-row-parse-tenant-id = app_role_permission row parse failed (tenant_id): {$arg0}
dao-app-role-row-parse-code = app_role row parse failed (code): {$arg0}
dao-app-role-row-parse-created-at = app_role row parse failed (created_at): {$arg0}
dao-app-role-row-parse-description = app_role row parse failed (description): {$arg0}
dao-app-role-row-parse-id = app_role row parse failed (id): {$arg0}
dao-app-role-row-parse-name = app_role row parse failed (name): {$arg0}
dao-app-role-row-parse-tenant-id = app_role row parse failed (tenant_id): {$arg0}
dao-app-role-row-parse-updated-at = app_role row parse failed (updated_at): {$arg0}
dao-app-role-update-connection = app_role update get connection failed: {$arg0}
dao-app-role-update-session = app_role update get session failed: {$arg0}
dao-app-role-update-update = app_role update update failed: {$arg0}
dao-app-session-create-connection = app_session create get connection failed: {$arg0}
dao-app-session-create-insert = app_session create insert failed: {$arg0}
dao-app-session-create-session = app_session create get session failed: {$arg0}
dao-app-session-delete-connection = app_session delete get connection failed: {$arg0}
dao-app-session-delete-delete = app_session delete delete failed: {$arg0}
dao-app-session-delete-session = app_session delete get session failed: {$arg0}
dao-app-session-find-by-session-id-query = app_session find-by-session-id query failed: {$arg0}
dao-app-session-find-by-user-id-query = app_session find-by-user-id query failed: {$arg0}
dao-app-session-list-connection = app_session list get connection failed: {$arg0}
dao-app-session-list-query = app_session list query failed: {$arg0}
dao-app-session-list-session = app_session list get session failed: {$arg0}
dao-app-session-row-parse-device-id = app_session row parse failed (device_id): {$arg0}
dao-app-session-row-parse-expire-time = app_session row parse failed (expire_time): {$arg0}
dao-app-session-row-parse-ip = app_session row parse failed (ip): {$arg0}
dao-app-session-row-parse-last-active = app_session row parse failed (last_active): {$arg0}
dao-app-session-row-parse-login-time = app_session row parse failed (login_time): {$arg0}
dao-app-session-row-parse-session-id = app_session row parse failed (session_id): {$arg0}
dao-app-session-row-parse-tenant-id = app_session row parse failed (tenant_id): {$arg0}
dao-app-session-row-parse-user-agent = app_session row parse failed (user_agent): {$arg0}
dao-app-session-row-parse-user-id = app_session row parse failed (user_id): {$arg0}
dao-app-session-update-last-active-update = app_session update-last-active update failed: {$arg0}
dao-app-user-create-connection = app_user create get connection failed: {$arg0}
dao-app-user-create-insert = app_user create insert failed: {$arg0}
dao-app-user-create-session = app_user create get session failed: {$arg0}
dao-app-user-delete-connection = app_user delete get connection failed: {$arg0}
dao-app-user-delete-delete = app_user delete delete failed: {$arg0}
dao-app-user-delete-session = app_user delete get session failed: {$arg0}
dao-app-user-device-block-update = app_user_device block update failed: {$arg0}
dao-app-user-device-count-connection = app_user_device count get connection failed: {$arg0}
dao-app-user-device-count-empty = app_user_device COUNT(*) returned no rows: {$arg0}
dao-app-user-device-count-query = app_user_device count query failed: {$arg0}
dao-app-user-device-count-session = app_user_device count get session failed: {$arg0}
dao-app-user-device-insert = app_user_device insert failed: {$arg0}
dao-app-user-device-list-connection = app_user_device list get connection failed: {$arg0}
dao-app-user-device-list-query = app_user_device list query failed: {$arg0}
dao-app-user-device-list-session = app_user_device list get session failed: {$arg0}
dao-app-user-device-parse-count = app_user_device parse count failed: {$arg0}
dao-app-user-device-parse-exists-id = app_user_device parse exists id failed: {$arg0}
dao-app-user-device-query-exists = app_user_device query exists failed: {$arg0}
dao-app-user-device-row-parse-created-at = app_user_device row parse failed (created_at): {$arg0}
dao-app-user-device-row-parse-device-name = app_user_device row parse failed (device_name): {$arg0}
dao-app-user-device-row-parse-id = app_user_device row parse failed (id): {$arg0}
dao-app-user-device-row-parse-last-seen-at = app_user_device row parse failed (last_seen_at): {$arg0}
dao-app-user-device-row-parse-login-id = app_user_device row parse failed (login_id): {$arg0}
dao-app-user-device-row-parse-tenant-id = app_user_device row parse failed (tenant_id): {$arg0}
dao-app-user-device-row-parse-user-agent = app_user_device row parse failed (user_agent): {$arg0}
dao-app-user-device-unblock-update = app_user_device unblock update failed: {$arg0}
dao-app-user-device-update-last-seen-at = app_user_device update last_seen_at failed: {$arg0}
dao-app-user-ext-delete-connection = app_user_ext delete get connection failed: {$arg0}
dao-app-user-ext-delete-delete = app_user_ext delete delete failed: {$arg0}
dao-app-user-ext-delete-session = app_user_ext delete get session failed: {$arg0}
dao-app-user-ext-find-by-user-and-key-query = app_user_ext find-by-user-and-key query failed: {$arg0}
dao-app-user-ext-find-by-user-id-query = app_user_ext find-by-user-id query failed: {$arg0}
dao-app-user-ext-list-connection = app_user_ext list get connection failed: {$arg0}
dao-app-user-ext-list-query = app_user_ext list query failed: {$arg0}
dao-app-user-ext-list-session = app_user_ext list get session failed: {$arg0}
dao-app-user-ext-row-parse-created-at = app_user_ext row parse failed (created_at): {$arg0}
dao-app-user-ext-row-parse-field-key = app_user_ext row parse failed (field_key): {$arg0}
dao-app-user-ext-row-parse-field-type = app_user_ext row parse failed (field_type): {$arg0}
dao-app-user-ext-row-parse-field-value = app_user_ext row parse failed (field_value): {$arg0}
dao-app-user-ext-row-parse-id = app_user_ext row parse failed (id): {$arg0}
dao-app-user-ext-row-parse-tenant-id = app_user_ext row parse failed (tenant_id): {$arg0}
dao-app-user-ext-row-parse-updated-at = app_user_ext row parse failed (updated_at): {$arg0}
dao-app-user-ext-row-parse-user-id = app_user_ext row parse failed (user_id): {$arg0}
dao-app-user-ext-upsert = app_user_ext upsert: {$arg0}
dao-app-user-ext-upsert-connection = app_user_ext upsert get connection failed: {$arg0}
dao-app-user-ext-upsert-session = app_user_ext upsert get session failed: {$arg0}
dao-app-user-find-by-id-connection = app_user find-by-id get connection failed: {$arg0}
dao-app-user-find-by-id-query = app_user find-by-id query failed: {$arg0}
dao-app-user-find-by-id-session = app_user find-by-id get session failed: {$arg0}
dao-app-user-find-by-username-query = app_user find-by-username query failed: {$arg0}
dao-app-user-list-connection = app_user list get connection failed: {$arg0}
dao-app-user-list-query = app_user list query failed: {$arg0}
dao-app-user-list-session = app_user list get session failed: {$arg0}
dao-app-user-role-assign-connection = app_user_role assign get connection failed: {$arg0}
dao-app-user-role-assign-insert = app_user_role assign insert failed: {$arg0}
dao-app-user-role-assign-session = app_user_role assign get session failed: {$arg0}
dao-app-user-role-find-by-role-id-query = app_user_role find-by-role-id query failed: {$arg0}
dao-app-user-role-find-by-user-id-query = app_user_role find-by-user-id query failed: {$arg0}
dao-app-user-role-list-connection = app_user_role list get connection failed: {$arg0}
dao-app-user-role-list-query = app_user_role list query failed: {$arg0}
dao-app-user-role-list-session = app_user_role list get session failed: {$arg0}
dao-app-user-role-revoke-connection = app_user_role revoke get connection failed: {$arg0}
dao-app-user-role-revoke-delete = app_user_role revoke delete failed: {$arg0}
dao-app-user-role-revoke-session = app_user_role revoke get session failed: {$arg0}
dao-app-user-role-row-parse-grant-time = app_user_role row parse failed (grant_time): {$arg0}
dao-app-user-role-row-parse-role-id = app_user_role row parse failed (role_id): {$arg0}
dao-app-user-role-row-parse-scope = app_user_role row parse failed (scope): {$arg0}
dao-app-user-role-row-parse-tenant-id = app_user_role row parse failed (tenant_id): {$arg0}
dao-app-user-role-row-parse-user-id = app_user_role row parse failed (user_id): {$arg0}
dao-app-user-row-parse-created-at = app_user row parse failed (created_at): {$arg0}
dao-app-user-row-parse-id = app_user row parse failed (id): {$arg0}
dao-app-user-row-parse-last-login-at = app_user row parse failed (last_login_at): {$arg0}
dao-app-user-row-parse-password-hash = app_user row parse failed (password_hash): {$arg0}
dao-app-user-row-parse-status = app_user row parse failed (status): {$arg0}
dao-app-user-row-parse-tenant-id = app_user row parse failed (tenant_id): {$arg0}
dao-app-user-row-parse-updated-at = app_user row parse failed (updated_at): {$arg0}
dao-app-user-row-parse-username = app_user row parse failed (username): {$arg0}
dao-app-user-update-connection = app_user update get connection failed: {$arg0}
dao-app-user-update-session = app_user update get session failed: {$arg0}
dao-app-user-update-update = app_user update update failed: {$arg0}
dao-child-role-read = child_role read failed: {$arg0}
dao-dbnexus-init = dbnexus init failed: {$arg0}
dao-dbnexus-migrate = dbnexus migrate failed ({$arg0}): {$arg1}
dao-incr-parse-u64 = incr: existing value is not u64, key={$arg0}, value={$arg1}
dao-key-missing = key not found: {$arg0}
dao-oxcache-delete-sync = oxcache delete_sync failed: {$arg0}
dao-oxcache-exists-sync = oxcache exists_sync failed: {$arg0}
dao-oxcache-expire-set-with-ttl-sync = oxcache expire (set_with_ttl_sync) failed: {$arg0}
dao-oxcache-expire-sync = oxcache expire_sync failed: {$arg0}
dao-oxcache-get-sync = oxcache get_sync failed: {$arg0}
dao-oxcache-init = oxcache init failed: {$arg0}
dao-oxcache-set-with-ttl-sync = oxcache set_with_ttl_sync failed: {$arg0}
dao-oxcache-ttl-sync = oxcache ttl_sync failed: {$arg0}
dao-oxcache-update-set-with-ttl-sync = oxcache update (set_with_ttl_sync) failed: {$arg0}
dao-parent-role-read = parent_role read failed: {$arg0}
dao-role-closure-serialize = role_closure serialize failed: {$arg0}
dao-role-hierarchy-add-edge-insert = role_hierarchy add_edge insert failed: {$arg0}
dao-role-hierarchy-add-edge-session = role_hierarchy add_edge get session failed: {$arg0}
dao-role-hierarchy-connection = role_hierarchy get connection failed: {$arg0}
dao-role-hierarchy-query = role_hierarchy query failed: {$arg0}
dao-role-hierarchy-session = role_hierarchy get session failed: {$arg0}

# Protocol 错误（i18n 改造）

# apikey
apikey-clock = failed to get system time: {$arg0}
apikey-serialize = failed to serialize ApiKeyInfo: {$arg0}
apikey-deserialize = failed to deserialize ApiKeyInfo: {$arg0}
apikey-namespace-empty = namespace must not be empty
apikey-timeout-positive = timeout must be greater than 0
apikey-not-found = API Key not found
apikey-revoked = API Key revoked
apikey-expired = API Key expired

# jwt
jwt-secret-empty = JWT secret must not be empty
jwt-sign = JWT signing failed: {$arg0}
jwt-expired = JWT expired: {$arg0}
jwt-not-yet-valid = JWT not yet valid (nbf check failed): {$arg0}
jwt-invalid = JWT validation failed: {$arg0}
jwt-refresh-get-session = refresh_tokens get session failed: {$arg0}
jwt-refresh-get-conn = refresh_tokens get connection failed: {$arg0}
jwt-refresh-query = refresh_tokens query / field read failed: {$arg0}
jwt-refresh-insert = refresh_tokens INSERT failed: {$arg0}
jwt-refresh-update = refresh_tokens UPDATE failed: {$arg0}
jwt-refresh-select-child = refresh_tokens query child failed: {$arg0}

# sso / oidc / saml
sso-oidc-http-client-build = failed to build HTTP client: {$arg0}
sso-oidc-body-read = failed to read response body: {$arg0}
sso-oidc-body-utf8 = failed to decode response body as UTF-8: {$arg0}
sso-oidc-jwks-request = OIDC JWKS request failed: {$arg0}
sso-oidc-jwks-body-read = OIDC JWKS response body read failed: {$arg0}
sso-oidc-jwks-parse = OIDC JWKS response parse / deserialize failed: {$arg0}
sso-oidc-jwks-serialize = OIDC JWKS serialize failed: {$arg0}
sso-oidc-token-exchange = OIDC token exchange failed: {$arg0}
sso-oidc-token-body-read = OIDC token response body read failed: {$arg0}
sso-oidc-token-parse = OIDC token response parse failed: {$arg0}
sso-oidc-userinfo-request = OIDC userinfo request failed: {$arg0}
sso-oidc-userinfo-body-read = OIDC userinfo response body read failed: {$arg0}
sso-oidc-userinfo-parse = OIDC userinfo response parse failed: {$arg0}
sso-oidc-id-token-header-parse = OIDC id_token header parse failed: {$arg0}
sso-oidc-id-token-header-missing-kid = OIDC id_token header missing kid field
sso-oidc-jwks-key-not-found = OIDC JWKS public key not found for kid={$arg0}
sso-oidc-rsa-build = OIDC failed to build RSA public key: {$arg0}
sso-oidc-id-token-verify = OIDC id_token signature verification failed: {$arg0}
sso-oidc-id-token-expired = OIDC id_token expired
sso-oidc-id-token-invalid = OIDC id_token validation failed (expected {$arg0}, actual {$arg1})
sso-oidc-missing-id-token = OIDC token response missing id_token
sso-ticket-hmac-init = HMAC key initialization failed: {$arg0}
sso-ticket-serialize = failed to serialize SSO ticket: {$arg0}
sso-ticket-read = failed to read SSO ticket: {$arg0}
sso-ticket-deserialize = failed to deserialize SSO ticket: {$arg0}
sso-ticket-atomic-consume = failed to atomically consume SSO ticket: {$arg0}
sso-ticket-format-no-sig = SSO ticket format error: missing signature part
sso-ticket-sig-verify = SSO ticket signature verification failed: may be tampered or forged
sso-ticket-missing-or-expired = SSO ticket not found or expired
sso-saml-xml-parse = SAML XML parse failed: {$arg0}
sso-saml-not-on-or-after-parse = SAML NotOnOrAfter parse failed: {$arg0}
sso-redis-publish = Redis PUBLISH failed: {$arg0}

# oauth2 client
oauth2-http-client-build = failed to build HTTP client: {$arg0}
oauth2-body-read = failed to read response body: {$arg0}
oauth2-body-utf8 = failed to decode response body as UTF-8: {$arg0}
oauth2-token-endpoint = token endpoint request failed: {$arg0}
oauth2-introspect-endpoint = introspect endpoint request failed: {$arg0}
oauth2-client-id-empty = client_id must not be empty
oauth2-client-secret-empty = OIDC secret must not be empty
oauth2-username-empty = username must not be empty
oauth2-body-overflow = response body length overflow (E2)
oauth2-token-body-read = failed to read token response body: {$arg0}
oauth2-token-body-parse = failed to parse token response: {$arg0}
oauth2-introspect-body-read = failed to read introspection response body: {$arg0}
oauth2-introspect-body-parse = failed to parse introspection response: {$arg0}

# sign
sign-app-key-empty = app_key must not be empty
sign-timestamp-window = signature timestamp out of window
sign-nonce-replay = nonce replay
sign-mismatch = signature mismatch
sign-base64-decode = signature Base64 decode failed: {$arg0}
sign-clock = failed to get system time: {$arg0}

# system clock (generic)
system-clock-error = system clock error: {$arg0}

# social dao
dao-social-binding-get-session = social_binding get session failed: {$arg0}
dao-social-binding-get-conn = social_binding get connection failed: {$arg0}
dao-social-binding-query = social_binding query failed: {$arg0}
dao-social-binding-login-id-read = login_id read failed: {$arg0}
dao-social-binding-insert-select = INSERT/SELECT login_id failed: {$arg0}
dao-key-not-found = DAO key not found: {$arg0}

# oauth2_server
oauth2-server-authorize-serialize = AuthorizationCode serialize failed: {$arg0}
oauth2-server-authorize-deserialize = AuthorizationCode deserialize failed: {$arg0}
oauth2-server-token-serialize = TokenRecord serialize failed: {$arg0}
oauth2-server-token-deserialize = TokenRecord deserialize failed: {$arg0}
oauth2-server-token-invalid-client = invalid_client: {$arg0} not found
oauth2-server-client-serialize = OAuth2Client serialize failed: {$arg0}
oauth2-server-client-deserialize = OAuth2Client deserialize failed: {$arg0}
oauth2-server-client-hash = Argon2 hash failed: {$arg0}
oauth2-server-client-hash-format = Argon2 hash format invalid: {$arg0}
oauth2-server-introspect-invalid-client = invalid_client: {$arg0} not found
oauth2-server-revoke-invalid-client = invalid_client: {$arg0} not found

# Strategy/Web/Context/Backend errors (i18n migration)
strategy-limiter-storage = Limiter storage error: {$arg0}
strategy-system-time = System time error: {$arg0}
strategy-limiteron-op = limiteron operation failed: {$arg0}
strategy-ddos-global = DDoS global limiter error: {$arg0}
strategy-ddos-ip = DDoS limiter error for IP {$arg0}
strategy-ban-is-banned = ban_storage is_banned failed: {$arg0}
strategy-incr-ttl = limiter incr_with_ttl failed: {$arg0}
strategy-ban-save = ban_storage save failed: {$arg0}
strategy-interval-secs-zero = interval_secs must not be 0
strategy-burst-threshold-zero = burst_threshold must not be 0
strategy-max-scan-zero = max_scan must not be 0
strategy-login-id-empty = login_id must not be empty
strategy-perm-empty = permission string must not be empty
strategy-role-empty = role string must not be empty
strategy-maxmind-open = MaxMindDb failed to open file {$arg0}
strategy-maxmind-from-bytes = MaxMindDb failed to construct from bytes: {$arg0}
strategy-invalid-ip = invalid IP address: {$arg0}
strategy-maxmind-query = MaxMindDb query failed (IP={$arg0})
strategy-anomalous-serialize = failed to serialize login record: {$arg0}
strategy-analyzer-panic = analyzer task panicked: {$arg0}
strategy-alert-serialize = failed to serialize SecurityAlertEvent to JSON: {$arg0}
web-not-login = not logged in
web-token-invalid = token invalid or session not found
web-key-not-found = key not found: {$arg0}
ctx-tenant-context-missing = no tenant context, tenant isolation check failed
ctx-tenant-id-invalid = X-Tenant-Id is not a valid i64: {$arg0}
backend-http-client-build = failed to build HTTP client: {$arg0}
backend-http-request = HTTP request failed: {$arg0}
backend-response-deser = response deserialization failed: {$arg0}
backend-api-error = API error [{$arg0}]
backend-ca-load = failed to load CA certificate: {$arg0}
backend-client-cert-load = failed to load client certificate: {$arg0}
backend-token-invalid-or-expired = token invalid or expired
backend-auth-logic-not-injected = auth_logic not injected, switch_to unavailable
abac-expr-empty = abac_expr must not be empty
abac-cedar-schema-parse = Cedar schema parse failed: {$arg0}
abac-decision-cache-init = oxcache decision cache init failed: {$arg0}
abac-decision-cache-read = decision cache read failed: {$arg0}
abac-principal-parse = principal parse failed: {$arg0}
abac-action-parse = action parse failed: {$arg0}
abac-resource-parse = resource parse failed: {$arg0}
abac-context-parse = context parse failed: {$arg0}
abac-cedar-request-build = Cedar Request build failed: {$arg0}
abac-decision-cache-write = decision cache write failed: {$arg0}
abac-cedar-policy-parse = Cedar policy parse failed: {$arg0}
abac-cedar-policy-add = Cedar policy add failed: {$arg0}
abac-decision-cache-clear = decision cache clear failed: {$arg0}
abac-cedar-policy-delete = Cedar policy delete failed: {$arg0}
abac-cedar-policy-parse-id = Cedar policy {$arg0} parse failed: {$arg1}
abac-cedar-policy-add-id = Cedar policy {$arg0} add failed: {$arg1}
abac-temp-cedar-policy-parse = temp Cedar policy parse failed: {$arg0}
abac-temp-cedar-policy-add = temp Cedar policy add failed: {$arg0}
manager-not-init = GarrisonManager not initialized
manager-timeout-overflow = timeout overflowed u64: {$arg0}
router-not-login = not logged in
router-key-not-found = key not found: {$arg0}
server-token-empty = token is empty
server-no-permission = no permission
server-apikey-invalid = API Key invalid
server-external-tls-load = failed to load external TLS config: {$arg0}
server-external-addr-parse = external address parse failed: {$arg0}
server-external-server-error = external server error: {$arg0}
server-external-bind = failed to bind external port: {$arg0}
server-external-task-panic = external task panicked: {$arg0}
server-internal-addr-parse = internal address parse failed: {$arg0}
server-internal-server-error = internal server error: {$arg0}
server-internal-bind = failed to bind internal port: {$arg0}
server-internal-task-panic = internal task panicked: {$arg0}
plugin-on-login-failed = on_login failed
plugin-on-logout-failed = on_logout failed
plugin-on-permission-check-failed = on_permission_check failed
listener-on-event-failed = on_event failed
listener-signing-key-not-config = signing_key not configured, cannot export signature chain
listener-get-session = get_session failed: {$arg0}
listener-connection = connection failed: {$arg0}
listener-audit-insert = INSERT audit_logs failed: {$arg0}
listener-audit-select = SELECT audit_logs failed: {$arg0}
listener-audit-parse-tenant-id = audit_logs row parse failed (tenant_id): {$arg0}
listener-audit-parse-event-type = audit_logs row parse failed (event_type): {$arg0}
listener-audit-parse-login-id = audit_logs row parse failed (login_id): {$arg0}
listener-audit-parse-token = audit_logs row parse failed (token): {$arg0}
listener-audit-parse-ip = audit_logs row parse failed (ip): {$arg0}
listener-audit-parse-user-agent = audit_logs row parse failed (user_agent): {$arg0}
listener-audit-parse-metadata = audit_logs row parse failed (metadata): {$arg0}
listener-audit-parse-success = audit_logs row parse failed (success): {$arg0}
listener-audit-parse-created-at = audit_logs row parse failed (created_at): {$arg0}
listener-json-serialize = JSON serialization failed: {$arg0}
listener-hmac-key-invalid = HMAC key invalid: {$arg0}
limiter-eval-lua-empty = eval_lua returned empty result
cache-l1-get = oxcache L1 get failed: {$arg0}
cache-l1-perm-deser = L1 permission cache deserialize failed: {$arg0}
cache-l1-role-deser = L1 role cache deserialize failed: {$arg0}
cache-l2-perm-deser = L2 permission cache deserialize failed: {$arg0}
cache-l2-role-deser = L2 role cache deserialize failed: {$arg0}
cache-perm-serialize = permission list serialize failed: {$arg0}
cache-role-serialize = role list serialize failed: {$arg0}
cache-l1-set = oxcache L1 set_with_ttl failed: {$arg0}
cache-l1-delete = oxcache L1 delete failed: {$arg0}
json-serialize = JSON serialization failed: {$arg0}
json-deserialize = JSON deserialization failed: {$arg0}
json-template-parse = JSON template parse failed: {$arg0}

# Stp/Session/Core/Secure/Annotation/Account 错误（i18n 改造）
stp-dao-find-by-id = key not found: {$arg0}
stp-token-not-found = token not found: {$arg0}
stp-token-invalid = token invalid
stp-no-api-key = API Key not provided
stp-login-id-empty = login_id must not be empty
stp-token-empty = token must not be empty
stp-token-control-char = token contains control characters
stp-not-login = not logged in
stp-session-timeout = session idle timeout
stp-dao-connect = permission data source failure
stp-context-not-set = current request context not set (with_current_token not called)
secure-totp-init = TOTP init failed: {$arg0}
secure-base32-decode = Base32 decode failed: {$arg0}
secure-base64-decode = Base64 decode failed: {$arg0}
secure-utf8-decode = UTF-8 decode failed: {$arg0}
secure-cred-missing-colon = credential format error: missing colon separator
secure-auth-header-no-cred = Authorization header format error: missing credential part
secure-http-digest-no-params = Authorization header format error: missing params part
secure-http-digest-missing-nonce = missing nonce param
secure-http-digest-missing-response = missing response param
secure-http-digest-missing-nc = missing nc param
secure-http-digest-missing-cnonce = missing cnonce param
secure-sms-code-wrong = SMS code incorrect
secure-phone-empty = phone must not be empty
secure-email-code-wrong = Verification code incorrect
secure-email-empty = email must not be empty
secure-email-no-colon = email must not contain colon
secure-email-no-control-char = email must not contain control characters
secure-email-invalid-format = email format invalid
secure-email-code-mail-subject = Verification Code
secure-email-code-mail-body = Your verification code is: {$code}. It is valid for {$minutes} minutes.
    If you did not request this code, please ignore this email.
secure-counter-parse = counter value parse failed key={$arg0}: {$arg1}
secure-system-time = system time error: {$arg0}
secure-limiter-incr = limiteron incr_with_ttl failed: {$arg0}
core-token-invalid-or-expired = token invalid or expired
core-not-login = token invalid or expired
core-hmac-key-invalid = HMAC key length invalid: {$arg0}
core-simple-token-no-hmac-sep = Simple token format error: missing '.' HMAC separator
core-simple-token-no-dash-sep = Simple token format error: missing '-' separator
core-perm-empty = permission string must not be empty
core-role-empty = role string must not be empty
session-sim-token-serialize = serialize TokenSession failed: {$arg0}
session-sim-token-deserialize = deserialize TokenSession failed: {$arg0}
session-sim-account-deserialize = deserialize AccountSession failed: {$arg0}
session-account-not-found = AccountSession not found: {$arg0}
session-sim-account-serialize = serialize AccountSession failed: {$arg0}
session-token-not-found = token not found: {$arg0}
session-token-empty = token must not be empty
session-token-too-long = token length exceeded
session-sim-anon-deserialize = deserialize anonymous TokenSession failed: {$arg0}
session-sim-anon-serialize = serialize anonymous TokenSession failed: {$arg0}
session-mock-callback = mock callback failed
annotation-not-login = not logged in
annotation-no-token = token not provided
annotation-token-invalid = token invalid or session not found
annotation-tenant-id-invalid = X-Tenant-Id is not a valid i64: {$arg0}
account-argon2-param = Argon2 param invalid: {$arg0}
account-argon2-hash = Argon2 hash failed: {$arg0}
account-argon2-format = Argon2 hash format invalid: {$arg0}
account-argon2-verify = Argon2 verify failed: {$arg0}
account-bcrypt-hash = Bcrypt hash failed: {$arg0}
account-bcrypt-format = Bcrypt hash format invalid: {$arg0}
account-backup-serialize = backup_code secret_data serialize failed: {$arg0}
account-cred-deserialize = CredentialModel deserialize failed: {$arg0}
account-cred-serialize = CredentialModel serialize failed: {$arg0}
account-lockout-deserialize = deserialize LockoutState failed: {$arg0}
account-lockout-serialize = serialize LockoutState failed: {$arg0}
account-disable-serialize = serialize DisableEntry to JSON failed: {$arg0}
account-disable-deserialize = deserialize DisableEntry failed: {$arg0}

stp-token-invalid-or-not-login = token invalid or not logged in
stp-token-invalid-or-no-login-id = token invalid or missing login_id

# i18n migration completion (2026-07-18)

# session mock
session-mock-delete-failed = mock delete failed: {$arg0}
session-mock-read-failed = mock read failed: {$arg0}
session-mock-update-failed = mock update failed: {$arg0}

# sso completion
sso-mock-key-not-found = key not found
sso-oidc-token-status-error = token exchange response status error: {$arg0}
sso-oidc-userinfo-status-error = userinfo response status error: {$arg0}
sso-oidc-validate-not-implemented = OIDC id_token validation not implemented
sso-ticket-client-id-mismatch = SSO ticket client_id mismatch: expected {$arg0}, actual {$arg1}
sso-ticket-consumed-by-concurrent = SSO ticket consumed by concurrent request
sso-saml-signature-not-implemented = SAML signature verification not implemented
sso-saml-assertion-expired = SAML assertion expired: {$arg0}

# sign / apikey completion
sign-app-secret-too-short = app_secret too short: current {$arg0} bytes, requires at least {$arg1} bytes (256 bits)
apikey-namespace-too-long = namespace length cannot exceed 64 chars, actual: {$arg0}
apikey-namespace-invalid-chars = namespace only allows [a-zA-Z0-9_-], actual: {$arg0}
apikey-namespace-mismatch = API Key namespace mismatch: expected {$arg0}, actual {$arg1}
apikey-expired-cannot-rotate = API Key expired, cannot rotate

# keycloak completion
keycloak-discovery-body-read-failed = discovery body read failed: {$detail}
keycloak-dao-not-injected = KeycloakProvider DAO not injected, cannot cache JWKS (call with_dao to inject GarrisonDao)
keycloak-jwks-body-read-failed = JWKS body read failed: {$detail}
keycloak-jwks-serialize-failed = JWKS serialize failed: {$detail}
keycloak-jwks-cache-miss-after-fetch = cache miss after fetch_jwks (DAO write anomaly)
keycloak-jwks-deserialize-failed = JWKS deserialize failed: {$detail}
keycloak-token-immature = token not yet valid (nbf)
keycloak-token-invalid-audience = invalid audience
keycloak-token-invalid-issuer = invalid issuer
keycloak-exchange-code-body-read-failed = exchange_code body read failed: {$detail}

# server / backend completion
server-caller-not-owner-kickout = Caller is not the owner and lacks admin:sessions permission; kickout is forbidden
server-caller-not-owner-switch-to = Caller is not the owner and lacks admin:sessions permission; switch_to is forbidden
backend-auth-logic-not-injected-renew = auth_logic is not injected; renew_to_equivalent is unavailable

# oauth2_server completion
oauth2-server-client-invalid-scope = client does not allow scope: {$arg0}
oauth2-server-client-exists = client already exists: {$arg0}
oauth2-server-client-not-found = client not found: {$arg0}
oauth2-server-token-rate-limited-client = client rate limit exceeded: {$arg0}
oauth2-server-token-invalid-client-missing = invalid_client: client_id missing
oauth2-server-token-invalid-client-secret = invalid_client: client_secret incorrect
oauth2-server-token-unauthorized-auth-code = unauthorized: authorization code invalid or expired
oauth2-server-token-unauthorized-refresh = unauthorized: refresh token invalid or expired
oauth2-server-token-invalid-grant-refresh-mismatch = invalid_grant: refresh token client mismatch
oauth2-server-token-unauthorized-client-credentials = unauthorized: client credentials invalid
oauth2-server-token-unauthorized-password = unauthorized: username or password incorrect
oauth2-server-token-unauthorized-grant-no-verifier = unauthorized: missing code_verifier
oauth2-server-token-rate-limited-username = username rate limit exceeded: {$arg0}
oauth2-server-token-rate-limited-locked = account locked: {$arg0}
oauth2-server-token-invalid-grant-credentials = invalid_grant: credentials invalid
oauth2-server-authorize-unsupported-response-type = unsupported response_type: {$arg0}
oauth2-server-authorize-unsupported-code-challenge-method = unsupported code_challenge_method: {$arg0}
oauth2-server-authorize-code-challenge-empty = code_challenge cannot be empty
oauth2-server-authorize-redirect-uri-not-allowed = redirect_uri not allowed: {$arg0}
oauth2-server-authorize-code-verifier-invalid-length = code_verifier invalid length
oauth2-server-introspect-invalid-client-secret = invalid_client: client_secret incorrect
oauth2-server-revoke-invalid-client-secret = invalid_client: client_secret incorrect

# account completion
account-password-unsupported-hash-format = unsupported hash format: {$arg0}
account-backup-deserialize = backup_code secret_data deserialize failed: {$arg0}

# Stp layer errors (i18n refactor - session.rs hardcoded Chinese migration)

# SessionLogic trait default impl + GarrisonLogicDefault impl
stp-revoke-all-sessions-not-implemented = revoke_all_sessions requires GarrisonLogicDefault implementation
stp-get-active-sessions-not-implemented = get_active_sessions requires GarrisonLogicDefault implementation
stp-login-by-token-feature-required = login_by_token requires protocol-oauth2 or protocol-sso feature
stp-refresh-access-token-not-implemented-db = refresh_access_token not implemented: requires db-sqlite feature and RefreshTokenRotation injection
stp-refresh-access-token-no-rotation = refresh_access_token missing RefreshTokenRotation injection
stp-refresh-access-token-feature-required = refresh_access_token requires protocol-jwt + db-sqlite feature

# validate_login_with_token_inputs input validation
stp-token-length-too-short = token length too short: {$arg0} < 8
stp-token-length-too-long = token length exceeds limit: {$arg0} > 256

# login_inner NewDevice mode
stp-new-device-login-rejected-not-allowed = new device login rejected: NewDevice mode, new device login not allowed

# check_login_stateless / token_style feature validation
stp-jwt-token-style-requires-protocol-jwt = jwt token_style requires protocol-jwt feature
stp-stateless-requires-jwt-token-style = Stateless mode requires token_style=jwt
stp-stateless-requires-protocol-jwt = Stateless mode requires protocol-jwt feature
stp-unknown-token-style = unsupported token_style: {$arg0}

# auto_renewal config validation
stp-auto-renewal-no-auth-logic = auto_renewal_threshold enabled but auth_logic not injected, cannot renew
stp-auto-renewal-jwt-requires-protocol-jwt = auto_renewal_threshold enabled and token_style=jwt, but protocol-jwt feature not enabled

# MockAnomalyDetector failure simulation
stp-mock-login-detection-failed = mock login detection failed
stp-mock-check-login-detection-failed = mock check_login detection failed

# Authflow executor errors (i18n migration)
authflow-user-locked = User has been locked: {$arg0}
authflow-login-needs-builder = Login step requires CredentialBuilder, use execute_with_builder
authflow-login-needs-user-id = Login step requires user_id
authflow-credential-not-found = Credential of type {$arg0} not found
authflow-credential-verify-failed = Credential verification failed
authflow-enter-verification-code = Please enter {$arg0} verification code
authflow-mfa-needs-builder = MFA step requires CredentialBuilder, use execute_with_builder
authflow-mfa-needs-user-id = MFA step requires user_id
authflow-verify-failed = {$arg0} verification failed
authflow-max-depth-exceeded = AuthenticationFlow nesting exceeds {$arg0} level limit, possible circular reference
authflow-subflow-not-found = Sub-flow not found: {$arg0}
authflow-subflow-failed = Sub-flow {$arg0} failed: {$arg1}
authflow-subflow-pending = Sub-flow {$arg0} returned Pending, v0.6.0 does not support nested Pending propagation
authflow-social-needs-resolver = SocialProvider step requires SocialProviderResolver, use execute_with_full
authflow-complete-social-auth = Please complete {$arg0} social login authorization
authflow-social-login-failed = Social login {$arg0} failed: {$arg1}
authflow-sso-needs-resolver = SsoServer step requires SsoServerResolver, use execute_with_full
authflow-complete-sso-auth = Please complete SSO login: {$arg0}
authflow-sso-verify-failed = SSO ticket verification failed: {$arg0}
authflow-step-enter = Please enter {$arg0}
authflow-step-enter-code = Please enter {$arg0} verification code
authflow-step-complete-mfa = Please complete MFA verification
authflow-step-complete-social = Please complete {$arg0} social login
authflow-step-complete-sso = Please complete SSO login: {$arg0}
authflow-step-complete-action = Please complete required action: {$arg0}
authflow-step-complete-condition = Please complete conditional branch
authflow-step-complete-subflow = Please complete sub-flow: {$arg0}

# Config loader errors (i18n migration)
config-path-empty = configuration file path must not be empty
config-open-failed = failed to open configuration file [{$arg0}]: {$arg1}
config-too-large = configuration file too large [{$arg0}]: {$arg1} bytes, limit {$arg2} bytes

# Session event reasons / Stp hardcoded messages (i18n migration)
session-kickout-admin = admin forced logout
session-overflow-kickout = exceeded maximum login count
session-overflow-replaced = exceeded maximum login count, replaced by new session
stp-verify-token-not-implemented = verify_token requires subclass override delegating to core-token::Token::verify
stp-refresh-token-not-implemented = refresh_token requires protocol-jwt feature enabled
stp-refresh-token-jwt-only = refresh_token is only available when token_style=jwt
stp-mfa-not-passed = second factor authentication not passed

# Hardcoded string i18n fix (fix-i18n-hardcoded-strings)

# stp/util
stp-permission-empty = permission must not be empty
stp-role-empty = role must not be empty

# protocol/jwt
jwt-timeout-negative = timeout must not be negative: {$arg0}

# secure
secure-verify-totp-not-implemented = verify_totp not implemented
secure-generate-totp-not-implemented = generate_totp not implemented
secure-verify-sign-not-implemented = verify_sign not implemented
secure-create-sign-not-implemented = create_sign not implemented
sanitize-input-length-exceeded = input length {$arg0} exceeds maximum limit {$arg1}
digest-algo-unsupported = unsupported Digest algorithm: {$arg0}, only MD5 / SHA256 supported

# dao
dao-decr-parse-u64 = decr: existing value is not u64, key={$arg0}, value={$arg1}
counter-overflow = counter overflow: key={$arg0}

# strategy
strategy-login-frequency-exceeded = login frequency exceeded: IP {$arg0}
strategy-account-locked = account locked: login_id={$arg0}
strategy-geo-anomaly = geo anomaly detected: login_id={$arg0} last location {$arg1} differs from current
strategy-token-reuse-blocked = token reuse detected: login_id={$arg0} token has been blacklisted
strategy-device-anomaly = device anomaly: login_id={$arg0} device fingerprint {$arg1} not in known device list

# abac
abac-expr-length-exceeded = abac_expr length exceeds {$arg0} characters (DoS defense)
abac-expr-illegal-char = abac_expr contains policy terminator (suspected policy injection)
abac-expr-no-declaration = abac_expr must not declare permit/forbid policies
abac-expr-must-reference-context = abac_expr must reference principal/resource/action (reject pure literals)
abac-engine-not-init = AbacEngine not initialized, ABAC validation failed (fail-closed)
abac-login-id-missing = login_id not available during ABAC validation
abac-policy-denied = ABAC policy denied: action={$arg0}, resource={$arg1}

# credit
credit-alert-thresholds-empty = alert_thresholds must not be empty
credit-alert-thresholds-range = alert_thresholds[{$arg0}] = {$arg1} out of range [0, 100]
credit-alert-thresholds-order = alert_thresholds must be strictly ascending: {$arg0} <= {$arg1}

# web/cors
cors-credentials-wildcard = CORS config conflict: allow_credentials=true disallows wildcard "*" in allowed_origins

# context/tenant
ctx-tenant-id-missing = X-Tenant-Id header missing

# response_parts 专用 message keys（不含 detail，用于 HTTP 响应体）
# These keys are used by GarrisonError::response_parts_i18n() to return a
# generic description without variant detail, avoiding sensitive info
# leakage (one-to-one correspondence with response_parts() &'static str).
not-login-msg = Not logged in
not-permission-msg = Permission denied
not-role-msg = Role required
invalid-token-msg = Invalid token
token-revoked-msg = Token revoked
expired-token-msg = Token expired
dao-msg = Data access error
config-msg = Configuration error
internal-msg = Internal error
session-msg = Session error
annotation-msg = Annotation error
context-msg = Context error
oauth2-msg = OAuth2 error
network-msg = Network error
invalid-response-msg = Invalid upstream response
invalid-param-msg = Invalid parameter
not-implemented-msg = Not implemented
firewall-blocked-msg = Firewall blocked
disable-service-msg = Account disabled
not-safe-msg = Two-factor authentication required
invalid-state-transition-msg = Invalid state transition
sms-rate-limit-exceeded-msg = SMS rate limit exceeded
rate-limited-msg = Rate limited, please try again later
sms-verify-max-attempts-msg = Verification code attempts exceeded
sms-code-not-found-msg = Verification code not found or expired
sms-channel-recycled-msg = SMS channel recycled
email-rate-limit-exceeded-msg = Email sending too frequent
email-verify-max-attempts-msg = Verification max attempts exceeded
email-code-not-found-msg = Verification code not found or expired
email-channel-recycled-msg = Email channel recycled
credit-insufficient-msg = Credit insufficient
# Exception 变体依据 code 字段映射的 message
exception-not-login-msg = Not logged in
exception-not-permission-msg = Permission denied
exception-default-msg = Business exception

# Password policy rule messages (i18n migration)
policy-length-too-short = Password length {$arg0} is less than minimum required {$arg1}
policy-length-too-long = Password length {$arg0} exceeds maximum limit {$arg1}
policy-history-duplicate = Password matches a previous password
policy-blacklist-match = Password is in the blacklist
policy-contains-username = Password contains username
policy-common-password = Password is a commonly used password
policy-dictionary-word = Password is a dictionary word
policy-contains-email-prefix = Password contains email prefix
policy-hibp-requires-feature = HIBP check requires enabling the policy-hibp feature
policy-nist-length-too-short = Password length {$arg0} is less than NIST SP 800-63B minimum required {$arg1}
policy-max-age-expired = Password has expired, please change your password

# Session hijack detection messages (i18n migration)
session-ip-mismatch = Session IP mismatch: stored={$arg0}, current={$arg1}

# WAF deny reason messages (i18n migration)
waf-blacklist-path = Path {$arg0} matched blacklist
waf-danger-char-path = Path contains dangerous character {$arg0}
waf-danger-char-param = Parameter value contains dangerous character {$arg0}
waf-danger-char-header = Header value contains dangerous character {$arg0}
waf-banned-char = Path contains non-printable character {$arg0}
waf-dir-traversal = Path contains directory traversal pattern {$arg0}
waf-host-not-allowed = Host {$arg0} is not in the whitelist
waf-method-not-allowed = HTTP method {$arg0} is not in the allowed list
waf-header-banned = Header {$arg0} is in the banned list
waf-param-banned = Parameter {$arg0} is in the banned list

# WAF danger character descriptions
waf-danger-desc-double-slash = Double slash //
waf-danger-desc-backslash = Backslash \\
waf-danger-desc-semicolon = Semicolon ;
waf-danger-desc-null-byte = Null byte
waf-danger-desc-newline = Newline
waf-danger-desc-carriage-return = Carriage return
waf-danger-desc-pct-2e = Percent-encoded %2e
waf-danger-desc-pct-2f = Percent-encoded %2f
waf-danger-desc-pct-00 = Percent-encoded %00
waf-danger-desc-pct-5c = Percent-encoded %5c
waf-danger-desc-pct-3b = Percent-encoded %3b
waf-danger-desc-pct-0a = Percent-encoded %0a
waf-danger-desc-pct-0d = Percent-encoded %0d

# Confusable character detection messages (i18n migration)
confusable-suggestion = Consider replacing '{$arg0}' with '{$arg1}'

# OAuth2 PKCE / state / refresh messages (i18n migration)
oauth2-pkce-length-invalid = code_verifier length must be between 43-128, current {$arg0}
oauth2-pkce-chars-invalid = code_verifier only allows [A-Z]/[a-z]/[0-9]/-/./_/~ characters
oauth2-state-mismatch = state parameter mismatch, possible CSRF attack
oauth2-refresh-token-empty = refresh_token must not be empty

# Security alert detection messages (i18n migration)
alert-ip-changed = IP changed from {$arg0} to {$arg1}
alert-rapid-successive = {$arg0} tokens online simultaneously (threshold {$arg1})

# ABAC principal validation messages (i18n migration)
abac-principal-control-char = login_id contains control characters

# Core auth / permission messages (i18n migration)
core-switch-to-denied = switch_to denied: SwitchToGuard not configured, default deny-all
core-switch-to-not-implemented = switch_to not implemented: {$arg0} does not support identity switching
core-renew-not-implemented = renew_to_equivalent not implemented: {$arg0} does not support token renewal
core-account-no-permission = Account {$arg0} does not have permission: {$arg1}
core-account-no-role = Account {$arg0} does not have role: {$arg1}
core-permission-name-empty = permission name must not be empty
core-permission-already-registered = permission already registered: {$arg0}
core-permission-not-registered = permission not registered: {$arg0}

# Core token style messages (i18n migration)
core-token-parse-not-supported = {$arg0} token style does not support parse (no payload)
core-simple-secret-too-short = SimpleTokenStyle secret must be >= 32 bytes (aligned with JWT strong validation)
core-simple-token-uuid-invalid = Simple token format error: UUID part is invalid
core-simple-token-hmac-failed = Simple token HMAC verification failed
core-simple-requires-feature = SimpleTokenStyle requires secure-simple-token feature (A11 security fix)

# DAO not-implemented messages (i18n migration)
dao-not-implemented = {$arg0} not implemented for this backend

# Config validation messages (i18n migration)
config-jwt-secret-empty = jwt_secret must not be empty (when token_style=jwt)
config-jwt-algorithm-unsupported = Unsupported jwt_algorithm: {$arg0} (only HS256/HS384/HS512)
config-jwt-secret-too-short = jwt_secret length insufficient for {$arg0}, actual {$arg1} bytes — generate a high-entropy key with `openssl rand -base64 48`
config-jwt-secret-weak = predictable jwt_secret rejected: {$arg0}; weak keys can be brute-forced offline — generate a high-entropy key with `openssl rand -base64 48`
config-anon-timeout-invalid = anon_session_timeout must be > 0
config-l1-ttl-invalid = l1_cache_ttl_secs must be > 0
config-l2-ttl-invalid = l2_cache_ttl_secs must be > 0
config-l1-capacity-invalid = l1_cache_capacity must be > 0
config-redis-url-empty = redis_url must not be empty when rate_limit_backend=Redis
config-waf-method-case = waf_allowed_methods must be uppercase, actual: {$arg0}
config-sms-hourly-invalid = sms_hourly_limit must be > 0
config-sms-daily-invalid = sms_daily_limit must be >= sms_hourly_limit
config-sms-max-attempts-invalid = sms_verify_max_attempts must be > 0
config-sms-threshold-invalid = sms_unverified_threshold must be > 0
config-email-hourly-invalid = email_hourly_limit must be > 0
config-email-daily-invalid = email_daily_limit must be >= email_hourly_limit
config-email-max-attempts-invalid = email_verify_max_attempts must be > 0
config-email-threshold-invalid = email_unverified_threshold must be > 0
config-email-ttl-invalid = email_code_ttl must be > 0
config-anomalous-interval-invalid = anomalous_analyzer_interval_secs must be >= 60
config-anomalous-burst-invalid = anomalous_analyzer_burst_threshold must be > 0

# Session search messages (i18n migration)
session-search-keyword-too-long = keyword length exceeded: {$arg0} > {$arg1}
session-search-size-exceeded = size exceeded: {$arg0} > {$arg1}

# STP module messages (i18n migration)
stp-service-empty = service parameter must not be empty
stp-not-implemented = {$arg0} not implemented

# Strategy firewall messages (i18n migration)
firewall-anomalous-requires-login-id = AnomalousLogin requires login_id but ctx.login_id is None
firewall-anomalous-geo-parse-failed = Historical geo coordinate parse failed (key={$arg0}, value={$arg1})
firewall-anomalous-distance-exceeded = anomalous: user {$arg0} from {$arg1}, {$arg2}
firewall-geo-lat-out-of-range = GeoCoord: lat {$arg0} out of range [-90, 90]
firewall-geo-lon-out-of-range = GeoCoord: lon {$arg0} out of range [-180, 180]
firewall-geoip-not-in-whitelist = geoip: IP {$arg0} country code {$arg1} not in whitelist
firewall-geoip-no-country = geoip: IP {$arg0} cannot determine country, not in whitelist
firewall-geoip-in-blacklist = geoip: IP {$arg0} country code {$arg1} in blacklist
firewall-maxmind-city-decode-failed = MaxMindDb failed to decode City record (IP={$arg0}): {$arg1}
firewall-maxmind-country-decode-failed = MaxMindDb failed to decode Country record (IP={$arg0}): {$arg1}
firewall-rate-limit-no-login-id = RateLimit scope=User but ctx.login_id is None
firewall-rate-limit-no-tenant-id = RateLimit scope=Tenant but ctx.tenant_id is None
firewall-user-locked-permanent = user-lockout: user {$arg0} has been permanently locked
firewall-user-locked-temporary = user-lockout: user {$arg0} has been temporarily locked until {$arg1}

# Account module messages (i18n migration)
account-totp-parse-failed = TOTP secret_data parse failed (expected JSON with secret/step/digits fields): {$arg0}
account-disable-service-colon = service must not contain ':' (to avoid key injection): {$arg0}
account-disable-login-id-colon = login_id must not contain ':' (to avoid key injection): {$arg0}

# Protocol module messages (i18n migration)
oidc-algorithm-unsupported = OidcHandler only supports HS256/HS384/HS512, current algorithm not supported: {$arg0}
oidc-iss-mismatch = OIDC iss mismatch: token issuer does not match expected
oidc-aud-mismatch = OIDC aud mismatch: token audience does not include this client's client_id
temp-prefix-colon = prefix must not contain ':'
temp-ttl-invalid = ttl_seconds must be > 0
sso-secret-empty = SSO secret must not be empty (per security audit M5: ticket must be signed)

# Server / HTTP layer messages (i18n migration)
server-invalid-api-key = Invalid API Key
server-prometheus-encode-failed = Prometheus metrics encoding failed
server-internal-api-key-missing = internal_api_key not configured, internal API will reject all requests. Please set a non-empty value via with_internal_api_key()

# Remaining firewall / account / OIDC / OTel messages (i18n migration)
firewall-anomalous-need-login-id = AnomalousLogin requires login_id but ctx.login_id is None
firewall-ratelimit-user-none = RateLimit scope=User but ctx.login_id is None
firewall-ratelimit-tenant-none = RateLimit scope=Tenant but ctx.tenant_id is None
user-lockout-permanent = user {$arg0} has been permanently locked out
user-lockout-temporary = user {$arg0} has been temporarily locked out until {$arg1}
oidc-timeout-negative = timeout must not be negative: {$arg0}
otel-exporter-failed = OTLP exporter construction failed: {$arg0}
otel-provider-failed = Tracer provider setup failed: {$arg0}

# Gap report leftovers (config-load / dao-repo / cache / authflow / annotation)
config-rate-limit-backend-unsupported = GARRISON_RATE_LIMIT_BACKEND unsupported value '{$arg0}', only 'memory' or 'redis'
dao-user-device-limit-exceeded = user ({$arg0}) device limit reached, max {$arg1}
cache-l1-ttl-must-positive = UserCacheService::new: l1_ttl_secs must be > 0
cache-l2-ttl-must-positive = UserCacheService::new: l2_ttl_secs must be > 0
authflow-required-action-not-implemented = RequiredAction step not implemented in v0.6.0
annotation-parse-failed = cannot parse annotation from string (data variants require explicit construction): {$arg0}
stp-stateless-jwt-requires-revocation = token_style=jwt with Stateless mode requires enable_jwt_revocation (option 1: set enable_jwt_revocation=true; option 2: use JwtMode::Mixin; option 3: set allow_stateless_jwt_no_revocation=true)
config-unknown-token-style-jwt = unknown token_style: jwt (requires protocol-jwt feature)

# i18n audit 2026-09: key:: convention keys missing from FTL (P2 fill-up)

# apikey
apikey-namespace-reserved = API key namespace '{$arg0}' is reserved
apikey-scope-not-allowed = API key scope '{$arg0}' is not allowed

# authflow
authflow-unknown-custom-condition = unknown custom condition: {$arg0}
ip-whitelist-parse-failed = IP whitelist entry '{$arg0}' parse failed: {$arg1}

# limiteron circuit breaker
circuit-open = circuit breaker open: {$arg0}
circuit-limited = request rejected by circuit breaker (limited): {$arg0}
circuit-breaker = circuit breaker error: {$arg0}

# core token
core-simple-token-no-sep = Simple token format error: missing unit separator

# credit metering
credit-config-invalid = credit config invalid: {$arg0}
credit-dao = credit DAO error: {$arg0}
credit-get-consumed = credit get consumed failed: {$arg0}
credit-incr-failed = credit increment failed: {$arg0}
credit-query-history = credit query history failed: {$arg0}
credit-set-meta-failed = credit set meta failed: {$arg0}
credit-get-meta = credit get meta failed: {$arg0}
credit-reset-consumed = credit reset consumed failed: {$arg0}
credit-reset-meta = credit reset meta failed: {$arg0}
credit-reset-window-start = credit reset window start failed: {$arg0}
credit-get-window-start = credit get window start failed: {$arg0}
credit-set-window-start = credit set window start failed: {$arg0}
credit-consumed-parse-failed = credit consumed value parse failed: {$arg0}, {$arg1}
credit-meta-format-error = credit meta format error: {$arg0}, {$arg1}
credit-meta-consumed-parse-failed = credit meta consumed parse failed: {$arg0}, {$arg1}
credit-meta-limit-parse-failed = credit meta limit parse failed: {$arg0}, {$arg1}
credit-meta-window-start-parse-failed = credit meta window start parse failed: {$arg0}, {$arg1}
credit-meta-window-end-parse-failed = credit meta window end parse failed: {$arg0}, {$arg1}
credit-meta-cycle-param-parse-failed = credit meta cycle param parse failed: {$arg0}, {$arg1}
credit-meta-unknown-cycle-type = credit meta unknown cycle type: {$arg0}, {$arg1}
credit-window-start-parse-failed = credit window start parse failed: {$arg0}, {$arg1}

# dao
dao-role-hierarchy-add-edge-connection = role hierarchy add edge connection failed: {$arg0}
dao-role-hierarchy-delete-edge-session = role hierarchy delete edge session failed: {$arg0}
dao-role-hierarchy-delete-edge-connection = role hierarchy delete edge connection failed: {$arg0}
dao-role-hierarchy-delete-edge = role hierarchy delete edge failed: {$arg0}
dao-social-binding-session = social binding session failed: {$arg0}
dao-social-binding-conn = social binding connection failed: {$arg0}
dao-social-binding-insert-session = social binding insert session failed: {$arg0}
dao-social-binding-insert-conn = social binding insert connection failed: {$arg0}
dao-social-binding-insert = social binding insert failed: {$arg0}
embedded-migrations-tempdir = create temp dir for embedded migrations failed: {$arg0}
embedded-migrations-write = write embedded migration file failed: {$arg0}
embedded-migrations-readdir = read embedded migrations dir failed: {$arg0}
embedded-migrations-direntry = read embedded migration dir entry failed: {$arg0}
dao-app-role-permission-find-by-role-id-query = find role permissions by role id query failed: {$arg0}
dao-app-role-permission-find-by-permission-id-query = find role permissions by permission id query failed: {$arg0}
dao-app-role-permission-row-parse-permission-id = parse permission id failed: {$arg0}
dao-app-user-device-row-parse-device-identifier = parse device identifier failed: {$arg0}
dao-eval-lua-unsupported-script = eval_lua unsupported script for this backend: {$arg0}
dao-oxcache-cas-get-sync = oxcache CAS get (sync) failed: {$arg0}
dao-oxcache-cas-set-sync = oxcache CAS set (sync) failed: {$arg0}
dao-oxcache-eval-lua = oxcache eval_lua failed: {$arg0}
dao-oxcache-sync-api-incompatible-with-redis = _sync API (set_if_absent/incr/decr/get_and_delete) is incompatible with the Redis L2 backend; use the async APIs or remove with_redis_config

# password policy / HIBP
hibp-client-build-failed = HIBP client build failed: {$arg0}
hibp-http-status = HIBP request returned unexpected status: {$arg0}, {$arg1}
hibp-request-failed = HIBP request failed: {$arg0}, {$arg1}
hibp-body-read-failed = HIBP response body read failed: {$arg0}

# jwt
jwt-secret-too-short = jwt secret too short: {$arg0}, {$arg1}
jwt-refresh-login-id-parse-failed = jwt refresh login id parse failed: {$arg0}, {$arg1}
jwt-refresh-cleanup-get-session = jwt refresh cleanup: get session failed: {$arg0}
jwt-refresh-cleanup-get-conn = jwt refresh cleanup: get connection failed: {$arg0}
jwt-refresh-cleanup-delete = jwt refresh cleanup: delete failed: {$arg0}
jwt-revoked = JWT has been revoked: {$arg0}

# limiteron
limiteron-ban-history-format-error = limiteron ban history format error: {$arg0}, {$arg1}
limiteron-ban-history-parse-ban-times = limiteron ban history parse ban_times failed: {$arg0}, {$arg1}
limiteron-ban-history-parse-last-banned = limiteron ban history parse last_banned failed: {$arg0}, {$arg1}
limiteron-ban-times-parse-failed = limiteron ban times parse failed: {$arg0}, {$arg1}
limiteron-eval-lua-parse-failed = limiteron eval_lua result parse failed: {$arg0}
limiteron-get-count-parse-failed = limiteron get count parse failed: {$arg0}, {$arg1}
limiteron-quota-count-parse-failed = limiteron quota count parse failed: {$arg0}, {$arg1}
limiteron-quota-meta-format-error = limiteron quota meta format error: {$arg0}, {$arg1}
limiteron-quota-limit-parse-failed = limiteron quota limit parse failed: {$arg0}, {$arg1}
limiteron-quota-window-start-parse-failed = limiteron quota window start parse failed: {$arg0}, {$arg1}
limiteron-quota-window-end-parse-failed = limiteron quota window end parse failed: {$arg0}, {$arg1}
limiteron-quota-window-start-datetime-failed = limiteron quota window start datetime failed: {$arg0}
limiteron-quota-window-end-datetime-failed = limiteron quota window end datetime failed: {$arg0}

# manager
manager-active-timeout-overflow = active_timeout overflowed u64: {$arg0}

# secure
secure-httpbasic-unsupported-scheme = HTTP Basic: unsupported auth scheme: {$arg0}
secure-httpdigest-unsupported-scheme = HTTP Digest: unsupported auth scheme: {$arg0}
secure-http-digest-missing-uri = HTTP Digest: missing uri parameter

# sso / saml
sso-oidc-body-exceeds-limit = SSO OIDC response body exceeds size limit: {$arg0}
saml-response-too-large = SAML response too large: {$arg0}, {$arg1}
sso-saml-assertion-replay = SAML assertion replay detected: {$arg0}
sso-saml-status-not-success = SAML response status is not Success: {$arg0}
sso-saml-destination-mismatch = SAML destination mismatch: {$arg0}, {$arg1}
sso-saml-audience-mismatch = SAML audience mismatch: {$arg0}, {$arg1}
sso-saml-not-before-parse = SAML NotBefore parse failed: {$arg0}
sso-saml-assertion-not-yet-valid = SAML assertion not yet valid: {$arg0}
sso-saml-in-response-to-unknown = SAML InResponseTo unknown or expired: {$arg0}
sso-saml-signature-value-decode = SAML signature value decode failed: {$arg0}
sso-saml-signature-bytes-decode = SAML signature bytes decode failed: {$arg0}
sso-saml-idp-public-key-parse-failed = SAML IdP public key parse failed: {$arg0}, {$arg1}

# stp
stp-login-ip-blocked = login blocked: IP {$arg0} is banned
stp-check-login-ip-blocked = check-login blocked: IP {$arg0} is banned
stp-apikey-ip-blocked = apikey request blocked: IP {$arg0} is banned
stp-simple-token-style-requires-secure-simple-token-feature = token_style=simple requires the secure-simple-token feature

# strategy / firewall
strategy-firewall-bruteforce-reason = brute force ban reason: attempts {$arg0} exceeds max {$arg1}
strategy-firewall-bruteforce-locked = IP {$arg0} is locked due to brute force
strategy-firewall-bruteforce-blocked = brute force blocked: IP {$arg0}, {$arg1}
strategy-firewall-ratelimit-blocked = rate limit blocked: scope {$arg0}, {$arg1}
strategy-limiter-eval-lua = rate limiter eval_lua failed: {$arg0}
strategy-ddos-global-blocked = DDoS global rate limit exceeded ({$arg0} req/s)
strategy-ddos-ip-blocked = DDoS per-IP rate limit exceeded for {$arg0} ({$arg1} req/s)
strategy-analyzer-shutdown-timeout = anomalous analyzer shutdown timeout: {$arg0}

# i18n audit 2026-09: loc! keys that referenced missing FTL messages (P3)
alipay-response-missing-oauth-token-response = alipay response missing alipay_system_oauth_token_response field
alipay-response-missing-access-token = alipay response missing access_token field
session-kickout-password-changed = password changed

# i18n audit 2026-09: raw English error messages migrated to key:: convention (P1)
abac-engine-already-initialized = AbacEngine already initialized
backend-unknown-error = Unknown error
config-confers-build-failed = confers build error: {$arg0}
config-unknown-token-style = unknown token_style: {$arg0}
config-unknown-cookie-same-site = unknown cookie_same_site: {$arg0} (expected Lax/Strict/None)
config-unknown-device-binding-mode = unknown device_binding_mode: {$arg0} (expected strict/loose/disabled)
config-timeout-must-positive = timeout must be positive
config-remember-me-timeout-mismatch = remember_me_timeout ({$arg0}) must be greater than timeout ({$arg1})
config-remember-me-timeout-positive = remember_me_timeout must be positive, got: {$arg0}
credential-already-exists = credential already exists: {$arg0}
credential-not-found = credential not found: {$arg0}
credential-backup-code-not-found = backup code credential not found in DAO: {$arg0}
credential-query-forbidden = caller {$arg0} cannot query credentials of {$arg1}
credential-update-forbidden = caller {$arg0} cannot update credential {$arg1}
credential-delete-forbidden = caller {$arg0} cannot delete credential {$arg1}
credential-transfer-forbidden = cannot transfer credential {$arg0}: {$arg1}
credential-totp-step-invalid = TOTP step must be > 0
ctx-invalid-header-name = invalid header name '{$arg0}': {$arg1}
ctx-invalid-header-value = invalid header value '{$arg0}': {$arg1}
ctx-invalid-status-code = invalid status code {$arg0}: {$arg1}
ctx-tenant-id-not-ascii = X-Tenant-Id not visible ASCII: {$arg0}
ctx-host-missing = Host header missing
ctx-host-not-ascii = Host not visible ASCII: {$arg0}
ctx-host-empty-subdomain = invalid Host '{$arg0}': empty subdomain
ctx-host-unknown-subdomain = unknown subdomain '{$arg0}'
ctx-auth-header-missing = Authorization header missing
ctx-auth-not-ascii = Authorization not visible ASCII: {$arg0}
ctx-auth-token-missing = missing token in Authorization header
ctx-auth-scheme-unsupported = unsupported auth scheme '{$arg0}' (expected Bearer)
permission-name-too-long = permission too long: {$arg0} bytes (max 256)
oauth2-server-client-id-invalid = invalid client_id: {$arg0}
jwt-refresh-token-consumed = refresh token not found or already consumed
oauth2-scope-handler-not-registered = scope handler not registered: {$arg0}
url-scheme-https-required = {$arg0} must be https or localhost, got: {$arg1}
sso-saml-signature-mismatch = SAML signature verification failed: signature value does not match SignedInfo
stp-apikey-feature-required = check_api_key requires the protocol-apikey feature (fail-closed: enable the feature or remove the check)
stp-mock-not-implemented = MockUserRepository::create not implemented
stp-param-login-id-missing = login_id not set in ParameterQuery context
stp-password-hasher-not-configured = password hasher not configured
stp-user-repo-not-configured = user repository not configured
stp-invalid-password = invalid password
stp-token-login-id-bound = token already associated with login_id: {$arg0}
stp-backend-already-init = Backend already initialized
stp-backend-not-init = Backend not initialized. Call init_backend() first.
testing-json-parse-error = JSON parse error: {$arg0}

# discovered during P1 migration (extra plain-English sites)
stp-unsupported-hash-format = unsupported hash format
ctx-auth-header-empty = empty Authorization header
ctx-tenant-jwt-verify-failed = JWT verify failed: {$arg0}
abac-engine-lock-poisoned = AbacEngine lock poisoned
config-auto-renewal-threshold-invalid = auto_renewal_threshold must be -1 or 0-100, got: {$arg0}
config-is-share-requires-concurrent = is_share=true requires is_concurrent=true
config-session-hover-timeout-exceeds = session_hover_timeout ({$arg0}) exceeds maximum allowed {$arg1} seconds (10 years)
stp-backend-lock-poisoned = Backend lock poisoned
session-ip-subnet-changed = IP subnet change detected: token={$arg0}, {$arg1}
invitation-code-invalid = invalid invitation code format: {$arg0}
invitation-code-collision = invitation code collision, please retry
invitation-code-not-found = invitation code not found
invitation-code-expired = invitation code has expired
invitation-code-revoked = invitation code {$arg0} has been revoked
invitation-code-exhausted = invitation code {$arg0} has reached maximum uses
invitation-too-many-attempts = too many redemption attempts from {$arg0}
invitation-ttl-invalid = invalid TTL value for invitation
invitation-max-uses-invalid = invalid max_uses value for invitation
invitation-count-invalid = invalid batch count for invitation
invitation-serialize-failed = invitation serialization failed: {$arg0}
# OAuth2 token endpoint errors (0.9.0 i18n sweep: RFC error-code prefixes kept)

oauth2-rate-limited-client = rate_limited: client requests too frequent, please retry later
oauth2-client-id-missing = invalid_client: client_id missing (provided neither in Authorization header nor body)
oauth2-client-not-exist = invalid_client: client_id {$client_id} does not exist
oauth2-client-secret-mismatch = invalid_client: client_secret mismatch
oauth2-grant-not-allowed-auth-code = unauthorized_client: authorization_code grant type not allowed for this client
oauth2-code-param-missing = invalid_request: missing code parameter
oauth2-code-verifier-missing = invalid_request: missing code_verifier parameter (PKCE enforced)
oauth2-redirect-uri-param-missing = invalid_request: missing redirect_uri parameter
oauth2-code-invalid-or-expired = invalid_grant: authorization code invalid or expired
oauth2-code-client-mismatch = invalid_grant: authorization code does not match client_id
oauth2-redirect-uri-mismatch = invalid_grant: redirect_uri differs from the one used at authorization time
oauth2-pkce-verify-failed = invalid_grant: PKCE code_verifier verification failed
oauth2-grant-not-allowed-refresh-token = unauthorized_client: refresh_token grant type not allowed for this client
oauth2-refresh-token-param-missing = invalid_request: missing refresh_token parameter
oauth2-refresh-token-invalid-or-expired = invalid_grant: refresh_token invalid or expired
oauth2-rotated-token-validate-failed = validation failed for rotated refresh_token
oauth2-refresh-token-client-mismatch = invalid_grant: refresh_token does not match client_id
oauth2-grant-not-allowed-client-credentials = unauthorized_client: client_credentials grant type not allowed for this client
oauth2-grant-not-allowed-password = unauthorized_client: password grant type not allowed for this client
oauth2-password-verifier-not-configured = unauthorized_grant_type: PasswordVerifier not configured for password grant type
oauth2-username-param-missing = invalid_request: missing username parameter
oauth2-password-param-missing = invalid_request: missing password parameter
oauth2-rate-limited-user = rate_limited: user requests too frequent, please retry later
oauth2-account-temp-locked = rate_limited: account temporarily locked, please retry later
oauth2-invalid-credentials = invalid_grant: invalid username or password

# ABAC validation errors (0.9.0 i18n sweep)

abac-expr-too-long = abac_expr exceeds {$max} characters (DoS protection)
abac-expr-illegal-chars = abac_expr contains illegal characters `{"{"};{"}"}` (possible policy injection)
abac-expr-policy-forbidden = abac_expr must not declare permit/forbid policies
abac-expr-must-reference-entity = abac_expr must reference principal/resource/action (plain literals rejected)
abac-engine-not-initialized = AbacEngine not initialized; ABAC check failed (fail-closed)

# Backend / macros / social registry / SDForge (0.9.0 i18n sweep)

backend-remote-base-url-invalid-scheme = invalid base_url scheme: {$arg0} (must be http:// or https://)
check-login-returned-false = Not logged in (check_login returned false)
social-provider-name-invalid = invalid social login provider name: {$provider}
social-provider-not-registered = social login provider not registered: {$provider}
caller-login-id-mismatch = caller_login_id does not match session.login_id
metrics-encode-failed = Prometheus metrics encoding failed

# Password reset (account-password-reset)
pwdreset-mail-subject = Password Reset Request
pwdreset-mail-body = You requested a password reset. Use the one-time token below within {$minutes} minutes: /reset-password?token={$token}

# OAuth2 authorize/resume endpoint (0.9.0 i18n sweep)
oauth2-resume-ticket-missing = missing ticket

# Observability log messages (tracing) internationalization

logs-noop-sms-sender-send-code = NoopSmsSender sending verification code (code omitted)
logs-csrf-set-cookie-build-failed = CSRF Set-Cookie build failed; skipped
logs-cors-allowlist-not-configured = frontend_separation CORS: cors_config.allowed_origins is not configured, so any Origin is echoed back; configure an allowlist to tighten the trust boundary
logs-cors-feature-disabled = frontend_separation CORS echoes any Origin (the web-cors feature is not enabled, so origin filtering by cors_config.allowed_origins is not possible); enable web-cors and configure an allowlist
logs-cors-origin-not-allowed = Origin did not match the CORS allowlist; skipping Allow-Origin echo
logs-sso-oidc-jwks-fetch-retry = sso-oidc-jwks-fetch: transport-layer error, retrying in 100ms: {$error}

# Log messages (tracing) i18n — r2 completion
# Completed keys: call sites were migrated to translate_detail but the keys were
# missing from both bundles, so logs printed the raw key (interrupted r2 sweep).

# OAuth2 back-channel logout deliverer (backchannel-logout)
logs-backchannel-logout-drain-complete = backchannel-logout drain completed
logs-backchannel-logout-drain-failed = backchannel-logout drain failed (retrying next round): {$error}
logs-backchannel-logout-max-ttl-retired = backchannel-logout delivery exceeded MaxTtl; marked failed and retired (no further delivery)
logs-backchannel-logout-delivery-retried = backchannel-logout delivery failed; counted as a retry

# Renewed-token response writing (router)
logs-renewed-token-header-name-invalid = failed to write the renewed token into the response header: token_name is invalid, skipped
logs-renewed-token-header-value-invalid = failed to write the renewed token into the response header: the token contains invalid characters, skipped
logs-renewed-token-cookie-value-invalid = failed to write the renewed token into Set-Cookie: the cookie string contains invalid characters, skipped
logs-renewed-token-cookie-build-rejected = failed to write the renewed token into Set-Cookie: rejected by build-site validation, skipped

# sdforge internal routes (server)
logs-sdforge-token-info-cross-user = get_token_info ownership check failed: cross-user access
logs-sdforge-session-cross-user = get_session ownership check failed: cross-user access

# Security alerts (strategy::alert)
logs-alert-anomaly-login = anomalous login alert
logs-alert-new-device-login = new device login alert
logs-alert-disable-triggered = ban triggered alert
logs-alert-privilege-escalation = privilege escalation alert
logs-alert-sensitive-operation = sensitive operation alert

# limiteron ban adapter
logs-limiteron-ban-record-parts-mismatch = limiteron-ban: ban record segment count mismatch; treated as not banned (fail-open)
logs-limiteron-ban-duration-parse-failed = limiteron-ban: failed to parse the ban record duration field; treated as not banned (fail-open)
logs-limiteron-ban-expires-at-parse-failed = limiteron-ban: failed to parse the ban record expires_at_ts field; treated as not banned (fail-open)
logs-limiteron-ban-times-parse-failed = limiteron-ban: failed to parse the ban record ban_times field; treated as not banned (fail-open)
logs-limiteron-ban-timestamp-invalid = limiteron-ban: invalid ban record timestamp; treated as not banned (fail-open)
logs-limiteron-ban-times-key-write-failed = limiteron-ban: failed to write the ban-times key; rolling back the main record
logs-limiteron-ban-history-key-write-failed = limiteron-ban: failed to write the ban-history key; rolling back the main record and the ban times
logs-limiteron-ban-cleanup-unimplemented = limiteron-ban: cleanup_expired_bans is not implemented (GarrisonDao has no iter API) and returns 0 — do not rely on this method to purge expired bans (TTL expiry plus the is_banned check cover it)
logs-limiteron-ban-list-unimplemented = limiteron-ban: list_bans is not implemented (GarrisonDao has no iter API) and returns an empty list — do not rely on this method for ban audit/enumeration (false negatives)

# Credit metering (multi-tenant-credit-metering)
logs-credit-concurrent-over-limit-rollback = credit: concurrent interleaving pushed the count over the limit; rolling back this consumption
logs-credit-rolling-window-start-delete-failed = credit: failed to delete window_start after a Rolling cycle reset (best-effort; the residual key is covered by TTL expiry or the next reset)
logs-credit-decr-rollback-failed = credit: failed to roll back decr (best-effort; denial semantics are unaffected)
logs-credit-reset-consumed-delete-failed = credit: reset failed to delete the consumed key (partial reset semantics; the remaining keys are no longer deleted)
logs-credit-reset-meta-delete-failed = credit: reset failed to delete the meta key (partial reset semantics; window_start is no longer deleted)
logs-credit-throttle-capacity-full = credit: activity throttle is at capacity; dropping this flush (rewritten outside the window)
logs-credit-throttle-write-failed = credit: activity flush write failed (the entry has been cleared; the activity is re-enqueued outside the window)
logs-credit-throttle-write-timeout = credit: activity flush write timed out (the entry has been cleared; the activity is re-enqueued outside the window)
logs-credit-throttle-window-dropped = credit: dropping the in-window activity flush summary (dropped = this flush is skipped; rewritten outside the window)

# Metrics registration (account / credit / observability)
logs-metrics-already-registered = {$arg0} is already registered in the prometheus default registry (duplicate new() or mixed use with register_to); returning an unregistered local instance — the registered instance is unaffected

# Web-framework integration guards
logs-actix-config-not-registered = GarrisonConfig is not registered as actix app_data (web::Data<Arc<GarrisonConfig>>); the auth extractor falls back to default_config and security parameters may be inconsistent — register it explicitly via App::app_data(web::Data::new(Arc::new(config)))
logs-actix-tenant-header-unverified = TenantContext extracts the tenant from the client-controlled X-Tenant-Id header without comparing it against the authenticated principal: any caller can declare any tenant ID. This extractor only performs format validation (numeric parsing) and does not authorize principal-to-tenant ownership. Do not rely on this header value for tenant isolation — use a server-trusted source such as ClaimTenantResolver (token claim), or validate the principal-to-tenant relation in the business layer
logs-backend-remote-plaintext-http = BackendRemote base_url uses plaintext http://; the X-API-Key may be eavesdropped on the network path — use https:// in production
logs-router-invalid-path-protected = GarrisonRouter::route_protected rejected an invalid path (must be non-empty and start with '/'); this route will not be protected by authentication
logs-router-duplicate-path-override = GarrisonRouter::route_protected registered the same path twice; the previous annotation is overridden (last-wins)

# Auth server bootstrap config (server::config)
logs-server-internal-api-key-too-short = server-internal-api-key-too-short: the internal API key is shorter than the minimum; 1.0 will turn this into a rejection — rotate to a key of at least 32 bytes
logs-server-external-login-unacknowledged = server-external-login-unacknowledged: the external login endpoint is exposed without acknowledgement; 1.0 will turn this into a rejection — pass the acknowledgement string external_login_ack
logs-server-wildcard-bind-default = server-wildcard-bind-default: unspecified wildcard binds become loopback in 1.0; for container deployments set with_external_bind(0.0.0.0) / with_internal_bind(0.0.0.0) explicitly
logs-config-cors-wildcard-without-credentials = config security rules: cors allowed_origins=["*"] without allow_credentials — any origin can read the responses; deployments exposing sensitive data should switch to an explicit origin allowlist

# CLI help (garrison-cli, cli-ops feature)
cli-about = Garrison operations tool

# Data erasure residual guidance (data-erasure)
compliance-erasure-residual-ip-artifacts = Other protection records linked to the IP (GeoIP cache, rate-limit window keys) expire naturally via TTL; extend this method if immediate erasure is required
compliance-erasure-residual-api-key = API keys: owned by the subject and carrying business-authorization semantics — revoke them after querying by owner through ApiKeyRepository (see the protocol-apikey document)
compliance-erasure-residual-audit-log = Audit logs: compliance retention outranks the right to erasure (PIPL Art. 47 / GDPR Art. 17(3)(b) legal-obligation exception); destroyed per the retention policy on expiry
compliance-erasure-residual-business-data = Business user profiles and business-side replicas: stored in the business party's own tables, unreachable by the framework
compliance-erasure-residual-verification-code = Verification code / email verification records: keyed by phone number/email (business mapping), expiring naturally via TTL (<= 1 hour)
compliance-erasure-residual-issued-jwt = Already issued JWTs: stateless signatures cannot be withdrawn before expiry (unless revocation is enabled, see config enable_jwt_revocation)

# i18n sweep 2026-10: hardcoded tracing / CLI / example strings wired to translate_detail

# Log messages (tracing) — account password reset
logs-pwdreset-mail-delivery-failed = password reset mail delivery failed
logs-pwdreset-history-append-replaced-generation-failed = password history append (replaced generation) failed; current-generation hash may be invisible to HistoryRule
logs-pwdreset-history-append-and-rollback-failed = password history append failed and credential rollback also failed; credential may be inconsistent

# Log messages (tracing) — config
logs-config-argon2-weak-params-accepted = password_hasher: argon2 m_cost {$cost} < OWASP floor {$floor} KiB — weak params explicitly accepted via allow_weak_argon2_params (memory-constrained deployment?)
logs-config-deprecated-key-migrated = deprecated config key "{$key}" (since {$since}) processed: {$outcome}; update your configuration before 1.0.0
logs-config-deprecated-key-unmigratable = deprecated config key "{$key}" (since {$since}) is no longer auto-mappable and will be rejected at 1.0.0; {$guidance}
config-deprecation-guidance-delete = delete it from your configuration
config-deprecation-guidance-rename = rename it manually
logs-config-rate-limit-redis-feature-disabled = rate-limit-redis feature disabled: rate limiting is per-process counting only; multi-instance deployments MUST enable rate-limit-redis for global limits
logs-config-rate-limit-memory-backend = rate_limit_backend=Memory: per-process counting only; multi-instance deployments MUST switch to Redis for global limits
logs-config-rate-limit-redis-active = rate-limit backend switched to Redis: login hook and RateLimitStrategy use dedicated limiter storage (session/token data stays in the original DAO)
config-rate-limit-redis-connect = Redis rate-limit backend connection failed (stage: {$stage}, endpoint: {$endpoint}, code: {$code})
config-deprecation-slot-lock-poisoned = deprecation slot lock must be available
logs-cookie-same-site-none-without-secure = cookie SameSite=None requires a Secure context (cookie_secure=false); downgraded to SameSite=Lax

# Log messages (tracing) — dao / cache / limiteron / audit
logs-dao-identifier-register-conflict-row-vanished = identifier register: unique conflict row vanished before tenant-scoped recheck, returning neutral Registered
logs-event-tx-dropped-without-commit = garrison-event-tx-dropped-without-commit: {$count} buffered event(s) discarded, kinds: [{$kinds}], open transaction rolled back via dbnexus drop cascade
logs-event-tx-discarded-after-commit-failure = garrison-event-tx-discarded-after-commit-failure: commit returned Err, {$count} buffered event(s) discarded without dispatch, kinds: [{$kinds}]
logs-event-tx-dispatch-cancelled-after-commit = garrison-event-tx-dispatch-cancelled-after-commit: commit succeeded but the dispatch future was cancelled mid-dispatch, {$dispatched} of {$total} event(s) dispatched, remaining discarded without dispatch, kinds: [{$kinds}]
logs-error-rejection-rate-limited = garrison rejection: rate limited
logs-limiteron-quota-consume-rollback-failed = quota consume over-limit rollback failed
logs-audit-mask-metadata-invalid-json = audit mask_metadata: metadata is not valid JSON, masking skipped and raw value kept
logs-cache-l3-write-back-failed = cache: L3 succeeded but write-back failed, returning uncached value
logs-cache-chain-read-failed-evict-and-fallback = cache: chain read/deserialize failed, evicting key and falling back to L3

# Log messages (tracing) — oauth2 / apikey
logs-oauth2-authorize-tenant-context-missing = oauth2 authorize: tenant context missing, falling back to default tenant 0 (consent memory keyed to default tenant)
logs-oauth2-refresh-rotation-not-configured = oauth2 refresh_token rotation not configured: serving refresh grant via DAO fallback without reuse detection — stolen refresh_token replay will NOT trigger chain revocation
logs-apikey-global-verify-enabled = apikey global verify enabled: verify() may validate keys from ANY namespace; prefer verify_with_namespace for tenant isolation

# Log messages (tracing) — secure
logs-secure-rollback-hourly-window-counter-failed = rollback hourly window counter failed
logs-secure-rollback-daily-window-counter-failed = rollback daily window counter failed
logs-secure-rollback-window-counter-failed = rollback {$label} window counter failed
logs-field-encryption-degenerate-non-primary-key = field-encryption: non-primary key is degenerate (single repeated byte); allowed for legacy decryption only — rotate it away via change-key

# Log messages (tracing) — server / http layer
logs-server-config-unrecognized-boolean = unrecognized boolean, falling back to default
logs-server-config-unrecognized-number = unrecognized number, falling back to default
logs-server-readiness-body-read-failed = readiness probe: upstream body read failed
logs-server-readiness-body-not-json = readiness probe: upstream body is not valid JSON
logs-server-apikey-auth-locked-window = api key auth locked: brute-force lockout window active
logs-server-apikey-duplicate-header = duplicate X-API-Key header rejected
logs-server-apikey-auth-failed = api key auth failed
logs-server-apikey-auth-locked-out = api key auth locked out
logs-server-inject-login-body-read-failed = inject_login_client_ip: body read failed (oversize or IO)
logs-server-sanitize-rejection-body-read-failed = sanitize_json_rejection: body read failed
logs-server-oauth2-state-without-refresh-rotation = OAuth2State constructed without RefreshTokenRotation: /oauth2/token refresh grant will serve via DAO fallback without reuse detection — refresh_token replay/chain revocation is UNAVAILABLE; inject TokenHandler::with_refresh_rotation to enable
logs-server-jwks-retention-zero-fallback = with_jwks_retention_secs(0) would retire Passive keys immediately; falling back to default {$secs}s
logs-server-discovery-jwks-algorithms-failed = discovery metadata jwks algorithms derivation failed
logs-server-discovery-scopes-failed = discovery metadata scopes derivation failed
logs-server-jwks-document-build-failed = jwks keystore document build failed
logs-sdforge-caller-login-id-missing = caller_login_id missing: ownership check is mandatory, rejecting
logs-server-consent-reconcile-removed-orphans = oauth2 consent startup reconcile: removed orphan consent rows of deleted clients
logs-server-consent-reconcile-no-orphans = oauth2 consent startup reconcile: no orphan rows
logs-server-consent-reconcile-failed = oauth2 consent startup reconcile failed (fail-open); orphan rows (if any) remain — retry on next restart or via reconcile_consents
logs-server-external-drain-timeout = external server graceful drain timeout exceeded, stopping to wait for in-flight requests
logs-server-internal-drain-timeout = internal server graceful drain timeout exceeded, stopping to wait for in-flight requests
logs-tls-watcher-start-failed = tls cert watcher start failed; certificate hot reload disabled
logs-tls-certificate-reloaded = tls certificate reloaded after file change
logs-tls-certificate-reload-failed = tls certificate reload failed; keeping the previous certificate
logs-tls-watcher-stopped = tls cert watcher stopped; certificate hot reload no longer available

# Log messages (tracing) — stp / strategy / web
logs-stp-password-lockout-reset-failed = password lockout reset-on-success failed (does not affect the login result)
logs-stp-password-account-locked = login_with_password: account locked
logs-stp-password-lockout-check-failed = password lockout check failed, degrading open (final defense is password verify)
logs-stp-password-lockout-record-failed = password lockout record_failure failed (does not affect the login result)
logs-stp-password-rehash-persist-failed = password rehash persist failed (does not affect the login result)
logs-stp-role-union-get-role-list-failed = role union cache: get_role_list failed, skip (fail-open)
logs-stp-role-union-no-sql-backend = role union cache: dao has no SQL backend, skip
logs-stp-role-union-precompute-failed = role union cache precompute failed, skip (fail-open)
logs-stp-role-union-write-failed = role union cache write failed (fail-open)
logs-stp-role-union-serialize-failed = role union cache serialize failed (fail-open)
logs-stp-remember-me-disabled = remember_me requested but disabled by config, using default timeout
logs-stp-jti-blacklist-snapshot-read-failed = jti blacklist snapshot read failed; revoked tokens may remain valid until natural expiry
logs-stp-invalidate-login-cache-logout-failed = invalidate_login_cache failed (does not affect the logout result)
logs-stp-invalidate-login-cache-kickout-failed = invalidate_login_cache failed (does not affect the kickout result)
logs-strategy-permission-cache-invalidate-failed = permission cache invalidation failed on logout (cache TTL will expire)
logs-strategy-role-cache-write-failed = role cache write failed (login_id={$login_id}, role={$role}): {$error}
strategy-rate-limit-adaptive-config-invalid = rate_limit: AdaptiveThresholdConfig invalid: {$error}
logs-request-id-middleware-completed = request_id_middleware: request completed
logs-warp-request-id-body-collect-failed = warp request_id: error body collect failed

# Panic / expect invariant messages (fail-loud internal invariants)
mfa-hkdf-okm-len-static = 32-byte OKM is within the HKDF-SHA256 output limit
mfa-webauthn-factor-registry-lock-poisoned = mfa webauthn factor registry lock must not be poisoned
cache-fallback-consumed-once = cache fallback must be consumed exactly once
cache-fallback-not-yet-executed = the error occurred before the fallback, which has not run yet
jwt-refresh-grace-entries-lock-poisoned = grace_entries lock must not be poisoned
secure-csprng-unavailable = OS CSPRNG unavailable
secure-aes-key-len-static = AES-256 key length is statically fixed at 32 bytes
secure-gcm-nonce-len-static = GCM nonce length is statically fixed at 12 bytes
server-inject-login-client-ip-invariant = should_inject implies client_ip is present

# HTTP response bodies (axum server middleware / sdforge routes)
server-http-body-invalid-json-msg = request body must be valid JSON
server-http-body-validation-failed-msg = request body failed validation
server-http-body-too-large-msg = request body exceeds size limit
sdforge-caller-login-id-required-msg = caller_login_id is required

# CLI (garrison-cli / garrison-healthcheck)
cli-field-encryption-feature-disabled = WARN: GARRISON_FIELD_ENCRYPTION_KEYS is set but the field-encryption feature is not enabled; the value is ignored
cli-change-key-report =
    change-key report (tenant={$tenant}, batch={$batch_size}, non-transactional: row-level atomic, re-run with old keys to converge after interruption):
      scanned: {$scanned}
      reencrypted: {$reencrypted}
      legacy_plaintext_reencrypted: {$legacy_plaintext_reencrypted}
      legacy_key_migrated: {$legacy_key_migrated}
      skipped_current_key: {$skipped_current_key}
      failed: {$failed}
cli-change-key-failed-row = failed-row: {$row}
cli-change-key-empty-scan-warning =
    WARNING: scanned = 0. The sensitive-key namespace of this deployment is likely
    NOT addressable via --db-url (production default stores KV in process-local oxcache,
    invisible to an external process). Do NOT remove old keys based on this run.
cli-check-key-report =
    check-key report (tenant={$tenant}, pattern={$pattern}):
      scanned: {$scanned}
      encrypted_ok: {$encrypted_ok}
      legacy_plaintext: {$legacy_plaintext}
      legacy_raw_key: {$legacy_raw_key}
      corrupt: {$corrupt}

      non-zero legacy counts mean migration is incomplete; run change-key to converge.
cli-check-key-corrupt-row = corrupt-row: {$row}
cli-check-key-empty-scan-hint =
    scanned = 0 likely means this deployment's KV data is not addressable via --db-url
    (production default keeps KV in process-local oxcache); see module docs.
cli-vacuum-kv-report = Vacuumed expired KV rows: {$count}
cli-vacuum-kv-swept = Swept legacy raw session-key rows: {$count}

cli-one-time-access-token-issued =
    Issued one-time access token for user '{$user}' (tenant {$tenant}).

    token:
    {$token}

    expires at: {$expires_at} (unix {$unix})

    one-time registry: app_user_ext field_key = {$field_key}

    SINGLE-USE SEMANTICS REQUIRE SERVER-SIDE WIRING: this framework
    does not consume the registry row automatically. Your login path must
    verify the token with the same signing secret AND atomically delete the
    registry row (find_by_user_and_key + delete) before creating a session;
    without that wiring the token is a short-lived bearer credential
    replayable within its TTL. Re-issuing for the same user replaces the
    registry row.
bin-healthcheck-failed = garrison-healthcheck: {$arg0}
bin-healthcheck-status = garrison-healthcheck: /healthz on 127.0.0.1:{$arg0} returned non-2xx status {$arg1}

# Official examples (examples/)
example-apikey-handler-built = [1] ApiKeyHandler constructed (allow_global_verify=true, example semantics)
example-apikey-verify-nonexistent = verify("nonexistent-key") -> Err(InvalidToken) OK (global verify enabled)
example-sso-envelope-consume = [Verify] subscriber-side verify_sso_message consuming the envelope:
example-sso-channel-message-count = channel must receive two messages
example-sso-envelope-verified = signature verified (last_seq={$seq}), business payload = {$payload}
example-sso-replay-rejected = replay of the same envelope rejected ({$reason})
example-sso-replay-not-rejected = replayed envelope must fail verification, but payload was returned: {$payload}
example-sso-bare-message-rejected = bare message (no envelope) rejected ({$reason})
example-sso-bare-message-not-rejected = bare unenveloped message must be rejected, but payload was returned: {$payload}

# i18n audit 2026-10: key:: convention keys referenced in code but missing from both bundles (P4 fill-up)
# Note: `waf-xxx-key` from the audit list is a documentation placeholder (src/web/axum/waf.rs:49), not a real key — no entry.
# Note: `auth-server-bootstrap-proxies-empty-entry`, `auth-server-bootstrap-proxy-not-private`,
#       `auth-server-field-encryption-no-keys` and `pwdreset-policy-violated-current-password` split out
#       of the audit keys above so each message keeps its own wording.

# account
account-argon2-params = argon2 password hashing failed: {$arg0}
account-argon2-pool-closed = the argon2 hashing thread pool is closed
action-token-jti-invalid = action token has an invalid jti: {$arg0}
action-token-purpose-mismatch = action token purpose mismatch: {$arg0}
credential-create-hash-gate = credential creation rejected by the stored-hash gate: {$arg0}
credential-possible-compromise = credential possibly compromised: {$arg0}
credential-update-hash-gate = credential update rejected by the stored-hash gate: {$arg0}
credential-verify-blocking = credential verification failed (blocking offload): {$arg0}
list-credentials = credential listing failed: {$arg0}
pwdreset-binding-missing = password reset session binding is missing
pwdreset-identifier-invalid = password reset identifier invalid ({$arg0})
pwdreset-password-credential-missing = no enabled password credential for this user
pwdreset-policy-violated = password policy violated: {$arg0}
pwdreset-policy-violated-current-password = the new password must differ from the current password
pwdreset-restricted-endpoint-denied = endpoint '{$arg0}' is not available to restricted password-reset sessions
pwdreset-session-not-found = password reset session not found
pwdreset-session-subject-mismatch = password reset session subject mismatch: session={$arg0}, token={$arg1}
pwdreset-subject-binding-mismatch = password reset subject binding mismatch: token-sub={$arg0}, binding={$arg1}
pwdreset-system-clock = system clock error: {$arg0}
pwdreset-tenant-binding-missing = password reset tenant binding is missing
pwdreset-tenant-mismatch = password reset token tenant mismatch
pwdreset-token-consume-failed = password reset token consume failed (already used or expired)
pwdreset-ttl-negative = password reset ttl must not be negative: {$arg0}
pwdreset-ttl-overflow = password reset ttl overflows i64: {$arg0}

# apikey
apikey-global-verify-disabled = global API key verification is disabled; use verify_with_namespace or enable it via with_allow_global_verify

# auth server bootstrap (bin/auth_server)
auth-server-bootstrap = invalid {$arg0}: '{$arg1}' — require an IPv4/IPv6 literal (e.g. 127.0.0.1 or 0.0.0.0), or for GARRISON_TRUSTED_PROXIES a comma-separated IP list (e.g. 10.0.0.1,127.0.0.1)
auth-server-bootstrap-proxies-empty-entry = GARRISON_TRUSTED_PROXIES contains an empty entry; expect a comma-separated IP list (e.g. 10.0.0.1,127.0.0.1)
auth-server-bootstrap-proxy-not-private = trusted proxy {$arg0} is not a private address; trusted proxies must be loopback/RFC1918/link-local/IPv6 ULA (public IPs can be spoofed on the path)
auth-server-fatal = FATAL: {$arg0}
auth-server-field-encryption = invalid GARRISON_FIELD_ENCRYPTION_KEYS entry '{$arg1}' ({$arg0}) — expect comma-separated key_id:hex64 entries
auth-server-field-encryption-no-keys = no field-encryption key configured: set GARRISON_FIELD_ENCRYPTION_KEYS (key_id:hex64,...) or disable the field-encryption feature

# backchannel logout queue
backchannel-http-client = back-channel logout HTTP client build failed: {$arg0}
backchannel-queue-connection = back-channel logout queue: get connection failed: {$arg0}
backchannel-queue-count = back-channel logout queue: count query failed: {$arg0}
backchannel-queue-find = back-channel logout queue: pending-entry scan failed: {$arg0}
backchannel-queue-get-session = back-channel logout queue: get session failed: {$arg0}
backchannel-queue-missing-row = back-channel logout queue: the claimed row no longer exists: {$arg0}
backchannel-queue-parse-count = back-channel logout queue: count parse failed: {$arg0}
backchannel-queue-pending = back-channel logout queue: pending list failed: {$arg0}

# cache
cache-l1-init = L1 cache initialization failed: {$arg0}
garrison-dao-cache = DAO cache backend error: {$arg0}
garrison-dao-cache-value-not-utf8 = DAO cache value is not valid UTF-8: {$arg0}

# cli (garrison-cli)
cli-change-key-empty-scan = refusing to report success: the sensitive-key namespace looks unreachable via --db-url (scanned = 0)
cli-change-key-rows-failed = change-key finished with rows needing attention: {$arg0}
cli-check-key-corrupt-rows = check-key found rows needing attention: {$arg0}
cli-check-key-empty-scan = refusing to report success: the sensitive-key namespace looks unreachable via --db-url (scanned = 0); see the module docs
cli-healthcheck-failed = healthcheck probe failed: {$arg0}
cli-healthcheck-join = healthcheck probe task join failed: {$arg0}
cli-healthcheck-status = /healthz on 127.0.0.1:{$arg0} returned non-2xx status {$arg1}
cli-key-source-missing = pass --key or set GARRISON_FIELD_ENCRYPTION_KEYS
cli-key-spec-empty-id = key id must not be empty: {$arg0}
cli-key-spec-format = expected key_id:hex, got: {$arg0}
cli-key-spec-hex-invalid = hex for key '{$arg0}' must be exactly 64 hex chars (32 bytes)
cli-key-specs-empty = pass at least one --key key_id:hex
cli-keygen-csprng = signing key generation failed (OS CSPRNG): {$arg0}
cli-one-time-exp-out-of-range = one-time token exp out of range: {$arg0}
cli-one-time-jti-missing = signed token has no jti claim
cli-one-time-migrate = database migration failed: {$arg0}
cli-one-time-secret-empty = signing secret must not be empty
cli-one-time-secret-missing = pass --secret or set GARRISON_JWT_SECRET
cli-one-time-ttl-invalid = ttl invalid: {$arg0} ({$arg1})
cli-one-time-user-not-active = user '{$arg0}' status is {$arg1} (only active users may be issued one-time credentials)
cli-one-time-user-not-found = no user '{$arg0}' in tenant {$arg1}
cli-runtime-build = tokio runtime build failed: {$arg0}
cli-user-hash-password-empty = password must not be empty
cli-user-hash-password-missing = pass --password or set GARRISON_CLI_PASSWORD
cli-user-hash-user-colon = username must not contain ':'
cli-user-hash-user-empty = username must not be empty

# config
config-csrf-enabled-unsupported = unsupported csrf_enabled value: {$arg0} (allowed: true/false, case-insensitive)
config-jwks-retention-must-positive = jwks_retention_secs must be positive
config-jwt-key-missing = JWT key missing from the configuration: {$arg0}
config-jwt-key-multiple-types = JWT key must not be configured with multiple types at once
config-jwt-key-unexpected-for-hs = JWT key '{$arg0}' is unexpected for an HMAC algorithm
config-mfa-chain-factor-unknown = unknown MFA chain factor: {$arg0}
config-password-hash-algorithm-unsupported = unsupported password hash algorithm: {$arg0}
config-password-hash-argon2-m-below-floor = argon2 m_cost {$arg0} is below the OWASP floor; algorithm: {$arg1}
config-password-hash-argon2-param-invalid = invalid argon2 parameter: {$arg0}
config-password-hash-argon2-pool-size-out-of-range = argon2 pool_size out of range: {$arg0}
config-password-hash-bcrypt-cost-out-of-range = bcrypt cost out of range: {$arg0}
config-refresh-grace-max-uses-zero = refresh_grace_max_uses must be >= 1, got: {$arg0}
config-refresh-grace-period-negative = refresh_grace_period_secs must not be negative, got: {$arg0}

# context
ctx-invalid-cookie-domain = invalid cookie domain for '{$arg0}'
ctx-invalid-cookie-max-age = invalid cookie max-age: {$arg0}
ctx-invalid-cookie-path = invalid cookie path for '{$arg0}'
ctx-invalid-cookie-same-site = invalid cookie same_site '{$arg0}': expected Lax/Strict/None

# dao
dao-app-password-history-append = app_password_history append failed: {$arg0}
dao-app-password-history-recent = app_password_history recent query failed: {$arg0}
dao-app-user-create-hash-gate = app_user create rejected by the stored-hash gate: {$arg0}
dao-app-user-identifier-find-owner = app_user_identifier find-owner failed: {$arg0}
dao-app-user-identifier-find-owner-in-tenant = app_user_identifier find-owner-in-tenant failed: {$arg0}
dao-app-user-identifier-register = app_user_identifier register failed: {$arg0}
dao-app-user-update-hash-gate = app_user update rejected by the stored-hash gate: {$arg0}
dao-app-webauthn-credential-conflict-lookup = webauthn credential conflict lookup failed: {$arg0}
dao-app-webauthn-credential-conflict-without-owner = webauthn credential conflict without an owning row: {$arg0}
dao-app-webauthn-credential-delete = webauthn credential delete failed: {$arg0}
dao-app-webauthn-credential-insert = webauthn credential insert failed: {$arg0}
dao-app-webauthn-credential-list = webauthn credential list failed: {$arg0}
dao-app-webauthn-credential-not-found = webauthn credential not found: {$arg0}
dao-app-webauthn-credential-query = webauthn credential query failed: {$arg0}
dao-app-webauthn-credential-sign-count-regression = webauthn sign counter regression: refusing to move the counter backwards ({$arg0})
dao-app-webauthn-credential-update = webauthn credential update failed: {$arg0}
dao-app-webauthn-credential-update-probe = webauthn credential update probe failed: {$arg0}
dao-app-webauthn-credential-update-probe-empty = webauthn credential update probe returned no row
dao-app-webauthn-credential-update-probe-parse = webauthn credential update probe row parse failed: {$arg0}
dao-conformance = failed to construct {$arg0}
dao-webauthn-credential-parse-attestation = webauthn credential row parse failed (attestation): {$arg0}
dao-webauthn-credential-parse-created = webauthn credential row parse failed (created): {$arg0}
dao-webauthn-credential-parse-cred-id = webauthn credential row parse failed (cred_id): {$arg0}
dao-webauthn-credential-parse-pk = webauthn credential row parse failed (public_key): {$arg0}
dao-webauthn-credential-parse-sign-count = webauthn credential row parse failed (sign_count): {$arg0}
dao-webauthn-credential-parse-tenant = webauthn credential row parse failed (tenant_id): {$arg0}
dao-webauthn-credential-parse-updated = webauthn credential row parse failed (updated): {$arg0}
dao-webauthn-credential-parse-user = webauthn credential row parse failed (user_id): {$arg0}
dao-webauthn-credential-sign-count-range = webauthn sign_count out of range: {$arg0}
event-tx-begin = event transaction begin failed: {$arg0}
event-tx-commit = event transaction commit failed: {$arg0}
event-tx-execute = event transaction execute failed: {$arg0}
event-tx-get-session = event transaction get session failed: {$arg0}
event-tx-rollback = event transaction rollback failed: {$arg0}
import-hash-argon2-format = argon2 hash import failed: params segment missing or incomplete
import-hash-argon2-m-cost = argon2 m_cost {$arg0} exceeds the import maximum {$arg1}
import-hash-argon2-p-cost = argon2 p_cost {$arg0} exceeds the import maximum {$arg1}
import-hash-argon2-t-cost = argon2 t_cost {$arg0} exceeds the import maximum {$arg1}
import-hash-bcrypt-cost = bcrypt cost {$arg0} exceeds the import maximum {$arg1}
import-hash-bcrypt-format = bcrypt hash import failed: cost segment missing or invalid
import-hash-unsupported = unsupported hash algorithm for import: {$arg0}
legacy-key-migration = legacy key migration is not supported on this backend (TTL query unsupported)

# jwt / jwks
jwks-clock-invalid = JWKS state clock invalid: {$arg0}
jwks-state-corrupt = JWKS state corrupt: {$arg0}
jwks-state-serialize = JWKS state serialize failed: {$arg0}
jwt-ec-curve-missing = EC key is missing the curve identifier
jwt-ec-curve-unsupported = unsupported EC curve: {$arg0}
jwt-ec-key = EC key build failed: {$arg0}
jwt-ec-pem-invalid = EC PEM parse failed: {$arg0}
jwt-ec-sec1-format = expected a SEC1 EC private key
jwt-ed-key = Ed25519 key build failed: {$arg0}
jwt-ed-pem-invalid = Ed25519 PEM parse failed: {$arg0}
jwt-ed-seed-len = Ed25519 seed length invalid
jwt-header-invalid = JWT header invalid: {$arg0}
jwt-jwks-symmetric = JWKS export does not support symmetric keys
jwt-jwks-unsupported-alg = JWKS export does not support algorithm {$arg0}
jwt-key-algorithm-mismatch = key algorithm mismatch: key={$arg0}, alg={$arg1}
jwt-keystore-no-active-key = keystore has no active key
jwt-kid-already-registered = kid '{$arg0}' is already registered
jwt-kid-retired = kid '{$arg0}' has been retired
jwt-kid-symmetric = kid must not reference a symmetric key
jwt-kid-unknown = unknown kid: {$arg0}
jwt-refresh-compensate-delete = refresh token compensation delete failed: {$arg0}
jwt-refresh-compensate-restore = refresh token compensation restore failed: {$arg0}
jwt-refresh-count-empty = refresh token count chain is empty
jwt-refresh-insert-and-compensate-failed = refresh token insert failed and compensation also failed: {$arg0}, {$arg1}
jwt-refresh-insert-rolled-back = refresh token insert rolled back: {$arg0}
jwt-refresh-reuse-rejected = refresh token reuse rejected: {$arg0}
jwt-rsa-key = RSA key build failed: {$arg0}
jwt-rsa-pem-invalid = RSA PEM parse failed: {$arg0}
jwt-sign-claims = JWT claim signing failed: {$arg0}
jwt-snapshot-kid-mismatch = key snapshot kid mismatch: {$arg0} != {$arg1}
jwt-snapshot-multiple-active = key snapshot has multiple active keys: {$arg0}

# mfa
mfa-aal-out-of-range = aal out of range ({$arg1}), got: {$arg0}
mfa-amr-method-unknown = unknown AMR method: {$arg0} ({$arg1})
mfa-recovery-batch-size-invalid = recovery code batch size invalid ({$arg1}), got: {$arg0}
mfa-recovery-misuse-parse = recovery misuse-state parse failed: {$arg0}
mfa-remember-secret-too-short = remember-me secret too short: {$arg0} ({$arg1})
mfa-remember-sign = remember-me token signing failed: {$arg0}
mfa-remember-ttl-overflow = remember-me ttl overflows i64: {$arg0}
mfa-webauthn-assertion-parse = webauthn assertion parse failed: {$arg0}
mfa-webauthn-factor-already-registered = webauthn factor is already registered
mfa-webauthn-factor-not-registered = webauthn factor is not registered
mfa-webauthn-subject-mismatch = webauthn assertion subject mismatch: asserted-for={$arg0}, session={$arg1}

# oauth2 server
oauth2-server-authorize-ticket-deserialize = authorize ticket deserialize failed: {$arg0}
oauth2-server-jwks-retirement-conflict = another instance rotated the key set; retirement deferred to that rotation
oauth2-server-jwks-rotation-conflict = another instance rotated the key set; reload and retry

# qrlogin
qrlogin-session-parse = QR login session parse failed: {$arg0}
qrlogin-session-serialize = QR login session serialize failed: {$arg0}
qrlogin-ticket-hmac-init = QR login ticket HMAC init failed: {$arg0}

# secure
secure-field-encryption-change-key = change-key batch size must be greater than zero
secure-field-encryption-config = field-encryption config error: {$arg0}
secure-field-encryption-dao = sensitive-key namespace operation rejected: {$arg0}
secure-field-encryption-decode = field decryption failed: {$arg0}
secure-field-encryption-open = field decryption failed: AAD, key or authentication tag mismatch
secure-field-encryption-seal = field encryption failed: {$arg0}
secure-field-encryption-utf8 = field value is not valid UTF-8: {$arg0}
secure-limiter-refund = limiter refund failed: {$arg0}
session-sim-primary-amr = primary AMR simulation failed: {$arg0}

# server
server-external-login-unacknowledged = external login is enabled on a non-loopback bind without acknowledgement ({$arg0}); pass the acknowledgement string external_login_ack
server-internal-api-key-too-short = internal API key is shorter than the minimum ({$arg0}); rotate to a key of at least 32 bytes

# sso
sso-client-secret-too-short = SSO client secret too short: {$arg0}, {$arg1}
sso-message-envelope-format = SSO message envelope format invalid
sso-message-envelope-serialize = SSO message envelope serialize failed: {$arg0}
sso-message-hmac-init = SSO message HMAC init failed: {$arg0}
sso-message-hmac-verify = SSO message HMAC verification failed
sso-message-seq-replay = SSO message sequence replay rejected: {$arg0}, {$arg1}
sso-saml-audience-not-configured = SAML audience is not configured; asserted audience: {$arg0}
sso-saml-destination-not-configured = SAML destination is not configured; asserted destination: {$arg0}
sso-server-secret-too-short = SSO server secret too short: {$arg0}, {$arg1}

# stp
stp-check-disable-token-session-not-found = check_disable: token session not found
stp-check-login-session-tenant-unbound = check_login: session has no tenant binding while a tenant context is present
stp-check-login-tenant-mismatch = check_login: session tenant does not match the request tenant
stp-check-login-tenant-unbound = check_login: token has no tenant binding while a tenant context is present
stp-login-id-control-char = login_id must not contain control characters
stp-login-id-sep = login_id must not contain the unit separator (U+001F)
stp-login-id-too-long = login_id too long: {$arg0} bytes (max {$arg1})
stp-login-id-whitespace = login_id must not contain whitespace
stp-password-account-locked = account locked: {$arg0}
stp-password-lock-check = password lockout check failed: {$arg0}
stp-password-lock-incr = password lockout failure count increment failed: {$arg0}
stp-password-lock-set = password lockout state write failed: {$arg0}
stp-refresh-token-revoked = refresh token has been revoked
stp-secondary-check-not-login = secondary check requires a logged-in session
strategy-sliding-window-count-parse = sliding window count parse failed: {$arg0}
strategy-sliding-window-key-empty = sliding window key must not be empty
strategy-sliding-window-response-length = sliding window script returned an unexpected response length

# webauthn
webauthn-attestation-format = attestation object format invalid: {$arg0}
webauthn-ceremony = webauthn ceremony failed: {$arg0}
webauthn-challenge-conflict = challenge key already claimed: {$arg0}
webauthn-challenge-deserialize = challenge deserialize failed: {$arg0}
webauthn-challenge-encode = challenge encode failed: {$arg0}
webauthn-challenge-getdel = challenge consume (GETDEL) failed: {$arg0}
webauthn-challenge-serialize = challenge serialize failed: {$arg0}
webauthn-challenge-setifabsent = challenge store (SETNX) failed: {$arg0}
webauthn-cred-id-encode = credential id encode failed: {$arg0}
webauthn-cred-row-encode = credential row encode failed: {$arg0}
webauthn-cred-row-format = credential row format invalid: {$arg0}
webauthn-cred-row-identity-mismatch = credential row identity mismatch (credential_id={$arg0})
webauthn-cred-row-parse = credential row parse failed: {$arg0}
webauthn-issuer-host-missing = issuer has no host: {$arg0}
webauthn-issuer-invalid = issuer invalid: {$arg0}
webauthn-rp-build = relying party build failed: {$arg0}
webauthn-rp-mismatch = relying party mismatch: {$arg0}
clientdata-parse = clientDataJSON parse failed: {$arg0}
clientdata-utf8 = clientDataJSON is not valid UTF-8: {$arg0}
cred-id = credential id decode failed: {$arg0}
start-auth = webauthn authentication start failed: {$arg0}
start-register = webauthn registration start failed: {$arg0}
update-state = webauthn state update failed: {$arg0}

# misc
warp-body-collect-failed = warp request_id: error body collect failed

# DAO conformance suite (dao::testing, `testing` feature — 下游自定义后端复用的契约测试)
# 断言消息保持原样（测试诊断文案，与仓库测试代码惯例一致）；panic/expect 失败路径与标签走 FTL。
dao-conformance-expect-ok-failed = [{$prefix}] {$what} must not fail: {$error}
dao-conformance-expect-err-failed = [{$prefix}] {$what}, got: {$actual}
dao-conformance-what-set-overwrite = set (overwrite)
dao-conformance-what-get-missing-key = get (missing key)
dao-conformance-what-delete-missing-key = delete (missing key)
dao-conformance-what-get-with-ttl-missing-key = get_with_ttl (missing key)
dao-conformance-what-incr-new-key = incr (new key)
dao-conformance-what-incr-increment = incr (second increment)
dao-conformance-what-decr-missing-key = decr (missing key)
dao-conformance-what-decr-zero = decr (stored zero)
dao-conformance-what-caui-missing-key = compare_and_update_if_greater (missing key)
dao-conformance-what-caui-smaller-value = compare_and_update_if_greater (smaller value)
dao-conformance-what-get-old-key = get (old key)
dao-conformance-what-get-new-key = get (new key)
dao-conformance-what-sia-new-key = set_if_absent (new key)
dao-conformance-what-sia-existing-key = set_if_absent (existing key)
dao-conformance-what-gd-missing-key = get_and_delete (missing key)
dao-conformance-what-cas-mismatch = compare_and_swap (expected mismatch)
dao-conformance-what-cas-match = compare_and_swap (expected match)
dao-conformance-what-cas-missing-key = compare_and_swap (missing key)
dao-conformance-what-keys-single-char = keys ('?' single-character pattern)
dao-conformance-what-keys-no-match = keys (no match)
dao-conformance-what-keys-after-delete = keys (after delete)
dao-conformance-what-keys-after-rename = keys (after rename)
dao-conformance-what-vacuum-drain = vacuum (drain pre-clean)
dao-conformance-what-vacuum = vacuum (main sweep)
dao-conformance-what-vacuum-2nd = vacuum (second, idempotent)
dao-conformance-expect-err-update-missing-key = update on a missing key must return Err(Dao)
dao-conformance-expect-err-expire-missing-key = expire on a missing key must return Err(Dao)
dao-conformance-expect-err-incr-non-numeric = incr on a non-numeric value must return Err(Dao) (no silent reset to zero)
dao-conformance-expect-err-incr-overflow = incr overflow on u64 must return Err(Dao)
dao-conformance-expect-err-caui-non-numeric = compare_and_update_if_greater on a non-numeric value must return Err(Dao)
dao-conformance-expect-err-rename-missing-key = rename on a missing key must return Err(InvalidParam) (trait contract)
dao-conformance-concurrent-sia-join-failed = [{$prefix}] set_if_absent task join failed
dao-conformance-concurrent-sia-error = [{$prefix}] set_if_absent must not fail concurrently: {$error}
dao-conformance-concurrent-gd-join-failed = [{$prefix}] get_and_delete task join failed
dao-conformance-concurrent-gd-error = [{$prefix}] get_and_delete must not fail concurrently: {$error}
dao-conformance-concurrent-incr-join-failed = [{$prefix}] incr task join failed
dao-conformance-concurrent-incr-error = [{$prefix}] incr must not fail concurrently: {$error}
dao-conformance-concurrent-decr-join-failed = [{$prefix}] decr task join failed
dao-conformance-concurrent-decr-error = [{$prefix}] decr must not fail concurrently: {$error}
dao-conformance-concurrent-caui-join-failed = [{$prefix}] compare_and_update_if_greater task join failed
dao-conformance-concurrent-caui-error = [{$prefix}] compare_and_update_if_greater must not fail concurrently: {$error}
dao-conformance-concurrent-cas-join-failed = [{$prefix}] compare_and_swap task join failed
dao-conformance-concurrent-cas-error = [{$prefix}] compare_and_swap must not fail concurrently: {$error}
dao-conformance-get-session-failed = [{$prefix}] get_session must not fail: {$error}
dao-conformance-connection-failed = [{$prefix}] connection must not fail: {$error}
dao-conformance-query-failed = [{$prefix}] query must not fail: {$error}
dao-conformance-query-returned-no-row = [{$prefix}] query must return a row: {$sql}
dao-conformance-val-column-read-failed = [{$prefix}] reading the val column failed: {$error}
dao-conformance-execute-failed = [{$prefix}] execute must not fail: {$error}
dao-conformance-injection-expected-dao-error = [{$prefix}] the injected failure must return a Dao error, got: {$actual}
dao-conformance-duplicate-binding-expected-already-bound = [{$prefix}] duplicate binding must return AlreadyBound, got: {$actual}
dao-conformance-bound-credential-not-found = [{$prefix}] a bound credential must be queryable, got: {$actual}
dao-conformance-query-must-succeed = [{$prefix}] query must succeed
dao-conformance-credential-update-must-succeed = [{$prefix}] updating an existing credential must succeed
dao-conformance-credential-must-exist-after-update = [{$prefix}] the credential must still exist after the update
dao-conformance-credential-must-exist-after-rollback = [{$prefix}] the credential must still exist after the rejected regression
dao-conformance-unbind-must-succeed = [{$prefix}] unbinding must succeed
dao-conformance-unbind-must-be-idempotent = [{$prefix}] repeated unbinding must stay Ok (idempotent)
cli-healthcheck-healthy = healthy: /healthz on 127.0.0.1:{$port} returned {$code}
