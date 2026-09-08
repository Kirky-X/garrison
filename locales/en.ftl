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

# --- Huawei Account Kit (huawei, sinnan custom provider) ---
huawei-token-request-failed = Huawei token request failed: {$detail}
huawei-token-response-parse-failed = Huawei token response parse failed: {$detail}
huawei-error-response = Huawei error response: {$detail}
huawei-token-response-missing-access-token = Huawei token response missing access_token field
huawei-get-user-info-failed-after-token-exchange = Huawei get_user_info failed after token exchange (code consumed, please re-authorize): {$detail}
huawei-userinfo-request-failed = Huawei userinfo request failed: {$detail}
huawei-userinfo-response-parse-failed = Huawei userinfo response parse failed: {$detail}
huawei-userinfo-business-error = Huawei userinfo business error: {$detail}
huawei-userinfo-response-missing-openID = Huawei userinfo response missing openID field

# ============================================================================
# DAO errors (i18n refactor)
# ============================================================================
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
server-internal-tls-load = failed to load internal TLS config: {$arg0}
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

# ============================================================================
# i18n migration completion (2026-07-18)
# ============================================================================

# --- session mock ---
session-mock-delete-failed = mock delete failed: {$arg0}
session-mock-read-failed = mock read failed: {$arg0}
session-mock-update-failed = mock update failed: {$arg0}

# --- sso completion ---
sso-mock-key-not-found = key not found
sso-oidc-token-status-error = token exchange response status error: {$arg0}
sso-oidc-userinfo-status-error = userinfo response status error: {$arg0}
sso-oidc-validate-not-implemented = OIDC id_token validation not implemented
sso-ticket-client-id-mismatch = SSO ticket client_id mismatch: expected {$arg0}, actual {$arg1}
sso-ticket-consumed-by-concurrent = SSO ticket consumed by concurrent request
sso-saml-signature-not-implemented = SAML signature verification not implemented
sso-saml-assertion-expired = SAML assertion expired: {$arg0}

# --- sign / apikey completion ---
sign-app-secret-too-short = app_secret too short: current {$arg0} bytes, requires at least {$arg1} bytes (256 bits)
apikey-namespace-too-long = namespace length cannot exceed 64 chars, actual: {$arg0}
apikey-namespace-invalid-chars = namespace only allows [a-zA-Z0-9_-], actual: {$arg0}
apikey-namespace-mismatch = API Key namespace mismatch: expected {$arg0}, actual {$arg1}
apikey-expired-cannot-rotate = API Key expired, cannot rotate

# --- keycloak completion ---
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

# --- server / backend completion ---
server-caller-not-owner-kickout = Caller is not the owner and lacks admin:sessions permission; kickout is forbidden
server-caller-not-owner-switch-to = Caller is not the owner and lacks admin:sessions permission; switch_to is forbidden
backend-auth-logic-not-injected-renew = auth_logic is not injected; renew_to_equivalent is unavailable

# --- oauth2_server completion ---
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

# --- account completion ---
account-password-unsupported-hash-format = unsupported hash format: {$arg0}
account-backup-deserialize = backup_code secret_data deserialize failed: {$arg0}

# ============================================================================
# Stp layer errors (i18n refactor - session.rs hardcoded Chinese migration)
# ============================================================================

# --- SessionLogic trait default impl + GarrisonLogicDefault impl ---
stp-revoke-all-sessions-not-implemented = revoke_all_sessions requires GarrisonLogicDefault implementation
stp-get-active-sessions-not-implemented = get_active_sessions requires GarrisonLogicDefault implementation
stp-login-by-token-feature-required = login_by_token requires protocol-oauth2 or protocol-sso feature
stp-refresh-access-token-not-implemented-db = refresh_access_token not implemented: requires db-sqlite feature and RefreshTokenRotation injection
stp-refresh-access-token-no-rotation = refresh_access_token missing RefreshTokenRotation injection
stp-refresh-access-token-feature-required = refresh_access_token requires protocol-jwt + db-sqlite feature

# --- validate_login_with_token_inputs input validation ---
stp-token-length-too-short = token length too short: {$arg0} < 8
stp-token-length-too-long = token length exceeds limit: {$arg0} > 256

# --- login_inner NewDevice mode ---
stp-new-device-login-rejected-not-allowed = new device login rejected: NewDevice mode, new device login not allowed

# --- check_login_stateless / token_style feature validation ---
stp-jwt-token-style-requires-protocol-jwt = jwt token_style requires protocol-jwt feature
stp-stateless-requires-jwt-token-style = Stateless mode requires token_style=jwt
stp-stateless-requires-protocol-jwt = Stateless mode requires protocol-jwt feature
stp-unknown-token-style = unsupported token_style: {$arg0}

# --- auto_renewal config validation ---
stp-auto-renewal-no-auth-logic = auto_renewal_threshold enabled but auth_logic not injected, cannot renew
stp-auto-renewal-jwt-requires-protocol-jwt = auto_renewal_threshold enabled and token_style=jwt, but protocol-jwt feature not enabled

# --- MockAnomalyDetector failure simulation ---
stp-mock-login-detection-failed = mock login detection failed
stp-mock-check-login-detection-failed = mock check_login detection failed

# ============================================================================
# Authflow executor errors (i18n migration)
# ============================================================================
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

# ============================================================================
# Config loader errors (i18n migration)
# ============================================================================
config-path-empty = configuration file path must not be empty
config-path-illegal-parent = configuration file path contains illegal parent directory reference (..): {$arg0}
config-open-failed = failed to open configuration file [{$arg0}]: {$arg1}
config-metadata-failed = failed to read configuration file metadata [{$arg0}]: {$arg1}
config-not-regular-file = configuration file path is not a regular file [{$arg0}]: {$arg1}
config-too-large = configuration file too large [{$arg0}]: {$arg1} bytes, limit {$arg2} bytes
config-read-failed = failed to read configuration file [{$arg0}]: {$arg1}

# ============================================================================
# Session event reasons / Stp hardcoded messages (i18n migration)
# ============================================================================
session-kickout-admin = admin forced logout
session-overflow-kickout = exceeded maximum login count
session-overflow-replaced = exceeded maximum login count, replaced by new session
stp-verify-token-not-implemented = verify_token requires subclass override delegating to core-token::Token::verify
stp-refresh-token-not-implemented = refresh_token requires protocol-jwt feature enabled
stp-refresh-token-jwt-only = refresh_token is only available when token_style=jwt
stp-mfa-not-passed = second factor authentication not passed

# ============================================================================
# Hardcoded string i18n fix (fix-i18n-hardcoded-strings)
# ============================================================================

# --- stp/util ---
stp-permission-empty = permission must not be empty
stp-role-empty = role must not be empty

# --- protocol/jwt ---
jwt-timeout-negative = timeout must not be negative: {$arg0}

# --- secure ---
secure-verify-totp-not-implemented = verify_totp not implemented
secure-generate-totp-not-implemented = generate_totp not implemented
secure-verify-sign-not-implemented = verify_sign not implemented
secure-create-sign-not-implemented = create_sign not implemented
sanitize-input-length-exceeded = input length {$arg0} exceeds maximum limit {$arg1}
digest-algo-unsupported = unsupported Digest algorithm: {$arg0}, only MD5 / SHA256 supported

# --- dao ---
dao-decr-parse-u64 = decr: existing value is not u64, key={$arg0}, value={$arg1}
counter-overflow = counter overflow: key={$arg0}

# --- strategy ---
strategy-login-frequency-exceeded = login frequency exceeded: IP {$arg0}
strategy-account-locked = account locked: login_id={$arg0}
strategy-geo-anomaly = geo anomaly detected: login_id={$arg0} last location differs from current
strategy-token-reuse-blocked = token reuse detected: login_id={$arg0} token has been blacklisted
strategy-device-anomaly = device anomaly: login_id={$arg0} device fingerprint {$arg1} not in known device list

# --- abac ---
abac-expr-length-exceeded = abac_expr length exceeds {$arg0} characters (DoS defense)
abac-expr-illegal-char = abac_expr contains policy terminator (suspected policy injection)
abac-expr-no-declaration = abac_expr must not declare permit/forbid policies
abac-expr-must-reference-context = abac_expr must reference principal/resource/action (reject pure literals)
abac-engine-not-init = AbacEngine not initialized, ABAC validation failed (fail-closed)
abac-login-id-missing = login_id not available during ABAC validation
abac-policy-denied = ABAC policy denied: action={$arg0}, resource={$arg1}

# --- credit ---
credit-alert-thresholds-empty = alert_thresholds must not be empty
credit-alert-thresholds-range = alert_thresholds[{$arg0}] = {$arg1} out of range [0, 100]
credit-alert-thresholds-order = alert_thresholds must be strictly ascending: {$arg0} <= {$arg1}

# --- web/cors ---
cors-credentials-wildcard = CORS config conflict: allow_credentials=true disallows wildcard "*" in allowed_origins

# --- context/tenant ---
ctx-tenant-id-missing = X-Tenant-Id header missing

# ============================================================================
# response_parts 专用 message keys（不含 detail，用于 HTTP 响应体）
# ============================================================================
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

# ============================================================================
# Password policy rule messages (i18n migration)
# ============================================================================
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

# ============================================================================
# Session hijack detection messages (i18n migration)
# ============================================================================
session-ip-mismatch = Session IP mismatch: stored={$arg0}, current={$arg1}

# ============================================================================
# WAF deny reason messages (i18n migration)
# ============================================================================
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

# --- WAF danger character descriptions ---
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

# ============================================================================
# Confusable character detection messages (i18n migration)
# ============================================================================
confusable-suggestion = Consider replacing '{$arg0}' with '{$arg1}'

# ============================================================================
# OAuth2 PKCE / state / refresh messages (i18n migration)
# ============================================================================
oauth2-pkce-length-invalid = code_verifier length must be between 43-128, current {$arg0}
oauth2-pkce-chars-invalid = code_verifier only allows [A-Z]/[a-z]/[0-9]/-/./_/~ characters
oauth2-state-mismatch = state parameter mismatch, possible CSRF attack
oauth2-refresh-token-empty = refresh_token must not be empty

# ============================================================================
# Security alert detection messages (i18n migration)
# ============================================================================
alert-ip-changed = IP changed from {$arg0} to {$arg1}
alert-rapid-successive = {$arg0} tokens online simultaneously (threshold {$arg1})

# ============================================================================
# ABAC principal validation messages (i18n migration)
# ============================================================================
abac-principal-control-char = login_id contains control characters

# ============================================================================
# Core auth / permission messages (i18n migration)
# ============================================================================
core-switch-to-denied = switch_to denied: SwitchToGuard not configured, default deny-all
core-switch-to-not-implemented = switch_to not implemented: {$arg0} does not support identity switching
core-renew-not-implemented = renew_to_equivalent not implemented: {$arg0} does not support token renewal
core-account-no-permission = Account {$arg0} does not have permission: {$arg1}
core-account-no-role = Account {$arg0} does not have role: {$arg1}
core-permission-name-empty = permission name must not be empty
core-permission-already-registered = permission already registered: {$arg0}
core-permission-not-registered = permission not registered: {$arg0}

# ============================================================================
# Core token style messages (i18n migration)
# ============================================================================
core-token-parse-not-supported = {$arg0} token style does not support parse (no payload)
core-simple-secret-too-short = SimpleTokenStyle secret must be >= 32 bytes (aligned with JWT strong validation)
core-simple-token-uuid-invalid = Simple token format error: UUID part is invalid
core-simple-token-hmac-failed = Simple token HMAC verification failed
core-simple-requires-feature = SimpleTokenStyle requires secure-simple-token feature (A11 security fix)

# ============================================================================
# DAO not-implemented messages (i18n migration)
# ============================================================================
dao-not-implemented = {$arg0} not implemented for this backend

# ============================================================================
# Config validation messages (i18n migration)
# ============================================================================
config-jwt-secret-empty = jwt_secret must not be empty (when token_style=jwt)
config-jwt-algorithm-unsupported = Unsupported jwt_algorithm: {$arg0} (only HS256/HS384/HS512)
config-jwt-secret-too-short = jwt_secret length insufficient for {$arg0}, actual {$arg1} bytes
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

# ============================================================================
# Session search messages (i18n migration)
# ============================================================================
session-search-keyword-too-long = keyword length exceeded: {$arg0} > {$arg1}
session-search-size-exceeded = size exceeded: {$arg0} > {$arg1}

# ============================================================================
# STP module messages (i18n migration)
# ============================================================================
stp-service-empty = service parameter must not be empty
stp-not-implemented = {$arg0} not implemented

# ============================================================================
# Strategy firewall messages (i18n migration)
# ============================================================================
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

# ============================================================================
# Account module messages (i18n migration)
# ============================================================================
account-totp-parse-failed = TOTP secret_data parse failed (expected JSON with secret/step/digits fields): {$arg0}
account-disable-service-colon = service must not contain ':' (to avoid key injection): {$arg0}
account-disable-login-id-colon = login_id must not contain ':' (to avoid key injection): {$arg0}

# ============================================================================
# Protocol module messages (i18n migration)
# ============================================================================
oidc-algorithm-unsupported = OidcHandler only supports HS256/HS384/HS512, current algorithm not supported: {$arg0}
oidc-iss-mismatch = OIDC iss mismatch: token issuer does not match expected
oidc-aud-mismatch = OIDC aud mismatch: token audience does not include this client's client_id
temp-prefix-colon = prefix must not contain ':'
temp-ttl-invalid = ttl_seconds must be > 0
sso-secret-empty = SSO secret must not be empty (per security audit M5: ticket must be signed)

# ============================================================================
# Server / HTTP layer messages (i18n migration)
# ============================================================================
server-rate-limited = Rate limited
server-invalid-api-key = Invalid API Key
server-prometheus-encode-failed = Prometheus metrics encoding failed
server-internal-api-key-missing = internal_api_key not configured, internal API will reject all requests. Please set a non-empty value via with_internal_api_key()

# ============================================================================
# Remaining firewall / account / OIDC / OTel messages (i18n migration)
# ============================================================================
firewall-anomalous-need-login-id = AnomalousLogin requires login_id but ctx.login_id is None
firewall-ratelimit-user-none = RateLimit scope=User but ctx.login_id is None
firewall-ratelimit-tenant-none = RateLimit scope=Tenant but ctx.tenant_id is None
user-lockout-permanent = user {$arg0} has been permanently locked out
user-lockout-temporary = user {$arg0} has been temporarily locked out until {$arg1}
oidc-timeout-negative = timeout must not be negative: {$arg0}
otel-exporter-failed = OTLP exporter construction failed: {$arg0}
otel-provider-failed = Tracer provider setup failed: {$arg0}

# ============================================================================
# Gap report leftovers (config-load / dao-repo / cache / authflow / annotation)
# ============================================================================
config-file-size-exceeded = config file actual size exceeds limit [{$arg0}]: {$arg1} bytes
config-rate-limit-backend-unsupported = GARRISON_RATE_LIMIT_BACKEND unsupported value '{$arg0}', only 'memory' or 'redis'
dao-user-device-limit-exceeded = user ({$arg0}) device limit reached, max {$arg1}
cache-l1-ttl-must-positive = UserCacheService::new: l1_ttl_secs must be > 0
cache-l2-ttl-must-positive = UserCacheService::new: l2_ttl_secs must be > 0
authflow-required-action-not-implemented = RequiredAction step not implemented in v0.6.0
annotation-parse-failed = cannot parse annotation from string (data variants require explicit construction): {$arg0}
stp-stateless-jwt-requires-revocation = token_style=jwt with Stateless mode requires enable_jwt_revocation (option 1: set enable_jwt_revocation=true; option 2: use JwtMode::Mixin; option 3: set allow_stateless_jwt_no_revocation=true)
config-unknown-token-style-jwt = unknown token_style: jwt (requires protocol-jwt feature)

# ============================================================================
# i18n audit 2026-09: key:: convention keys missing from FTL (P2 fill-up)
# ============================================================================

# --- apikey ---
apikey-namespace-reserved = API key namespace '{$arg0}' is reserved
apikey-scope-not-allowed = API key scope '{$arg0}' is not allowed

# --- authflow ---
authflow-unknown-custom-condition = unknown custom condition: {$arg0}
ip-whitelist-parse-failed = IP whitelist entry '{$arg0}' parse failed: {$arg1}

# --- limiteron circuit breaker ---
circuit-open = circuit breaker open: {$arg0}
circuit-limited = request rejected by circuit breaker (limited): {$arg0}
circuit-breaker = circuit breaker error: {$arg0}

# --- core token ---
core-simple-token-no-sep = Simple token format error: missing unit separator

# --- credit metering ---
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

# --- dao ---
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

# --- password policy / HIBP ---
hibp-client-build-failed = HIBP client build failed: {$arg0}
hibp-http-status = HIBP request returned unexpected status: {$arg0}, {$arg1}
hibp-request-failed = HIBP request failed: {$arg0}, {$arg1}
hibp-body-read-failed = HIBP response body read failed: {$arg0}

# --- jwt ---
jwt-secret-too-short = jwt secret too short: {$arg0}, {$arg1}
jwt-refresh-login-id-parse-failed = jwt refresh login id parse failed: {$arg0}, {$arg1}
jwt-refresh-cleanup-get-session = jwt refresh cleanup: get session failed: {$arg0}
jwt-refresh-cleanup-get-conn = jwt refresh cleanup: get connection failed: {$arg0}
jwt-refresh-cleanup-delete = jwt refresh cleanup: delete failed: {$arg0}
jwt-revoked = JWT has been revoked: {$arg0}

# --- limiteron ---
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

# --- manager ---
manager-active-timeout-overflow = active_timeout overflowed u64: {$arg0}

# --- secure ---
secure-httpbasic-unsupported-scheme = HTTP Basic: unsupported auth scheme: {$arg0}
secure-httpdigest-unsupported-scheme = HTTP Digest: unsupported auth scheme: {$arg0}
secure-http-digest-missing-uri = HTTP Digest: missing uri parameter

# --- sso / saml ---
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

# --- stp ---
stp-login-ip-blocked = login blocked: IP {$arg0} is banned
stp-check-login-ip-blocked = check-login blocked: IP {$arg0} is banned
stp-apikey-ip-blocked = apikey request blocked: IP {$arg0} is banned
stp-simple-token-style-requires-secure-simple-token-feature = token_style=simple requires the secure-simple-token feature

# --- strategy / firewall ---
strategy-firewall-bruteforce-reason = brute force ban reason: attempts {$arg0} exceeds max {$arg1}
strategy-firewall-bruteforce-locked = IP {$arg0} is locked due to brute force
strategy-firewall-bruteforce-blocked = brute force blocked: IP {$arg0}, {$arg1}
strategy-firewall-ratelimit-blocked = rate limit blocked: scope {$arg0}, {$arg1}
strategy-limiter-eval-lua = rate limiter eval_lua failed: {$arg0}
strategy-ddos-global-blocked = DDoS global rate limit exceeded ({$arg0} req/s)
strategy-ddos-ip-blocked = DDoS per-IP rate limit exceeded for {$arg0} ({$arg1} req/s)
strategy-analyzer-shutdown-timeout = anomalous analyzer shutdown timeout: {$arg0}

# ============================================================================
# i18n audit 2026-09: loc! keys that referenced missing FTL messages (P3)
# ============================================================================
alipay-response-missing-oauth-token-response = alipay response missing alipay_system_oauth_token_response field
alipay-response-missing-access-token = alipay response missing access_token field
session-kickout-password-changed = password changed

# ============================================================================
# i18n audit 2026-09: raw English error messages migrated to key:: convention (P1)
# ============================================================================
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

# --- discovered during P1 migration (extra plain-English sites) ---
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
