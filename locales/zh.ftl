# Bulwark 异常消息中文翻译（默认语言）
# 依据 spec exception-i18n 与 PRD 0.3.0 异常消息国际化
#
# 结构化错误 detail 约定（见 src/i18n.rs::parse_keyed_detail）：
#   调用方写为 `format!("some-key::{}", arg0)` 或 `format!("some-key::{}::{}", arg0, arg1)`，
#   `::` 分隔 key 与位置化参数，FTL 模板用 {$arg0}/{$arg1} 接收。
#   纯中文/英文串（无 `::`）视为旧式 detail，回退到 variant 默认 key + {$detail}。

not-login = 未登录: {$detail}
not-permission = 无权限: {$detail}
not-role = 无角色: {$detail}
invalid-token = Token 无效: {$detail}
expired-token = Token 已过期: {$detail}
dao = DAO 错误: {$detail}
config = 配置错误: {$detail}
internal = 内部错误: {$detail}
session = 会话错误: {$detail}
annotation = 注解错误: {$detail}
context = 上下文错误: {$detail}
oauth2 = OAuth2 错误: {$detail}
network = 网络错误: {$detail}
invalid-param = 参数无效: {$detail}
not-implemented = 未实现: {$detail}
exception = 业务异常[{$code}]: {$detail}

# 0.6.1 新增异常变体（依据 spec error-exceptions R-error-001~003）
disable-service = 账号已被封禁：service={$service}, until={$until}
not-safe = 未完成二次认证：{$reason}
invalid-state-transition = 非法状态转换：{$from} -> {$to}

# SMS 验证码渐进式限速异常（Phase 4 D4）
sms-rate-limit-exceeded = SMS 限速超出: {$window} 窗口
sms-verify-max-attempts = SMS 验证码尝试次数超限
sms-code-not-found = SMS 验证码不存在
sms-channel-recycled = SMS 通道已回收

# ============================================================================
# 社交登录异常消息（0.6.0 新增，依据 T021）
# ============================================================================

# --- 微信扫码登录（wechat）---
wechat-token-request-failed = 微信 token 请求失败: {$detail}
wechat-token-response-parse-failed = 微信 token 响应解析失败: {$detail}
wechat-error-response = 微信错误 {$code}: {$message}
wechat-response-missing-openid = 微信响应缺少 openid 字段
wechat-userinfo-request-failed = 微信用户信息请求失败: {$detail}
wechat-userinfo-response-parse-failed = 微信用户信息响应解析失败: {$detail}
wechat-userinfo-response-missing-openid = 微信用户信息响应缺少 openid 字段

# --- 微信小程序（wechat mini-app）---
wechat-mini-app-get-authorization-url-not-supported = WechatMiniAppProvider 不支持 get_authorization_url（小程序用 wx.login() 直接获取 js_code）
wechat-mini-app-jscode2session-request-failed = 微信小程序 jscode2session 请求失败: {$detail}
wechat-mini-app-jscode2session-response-parse-failed = 微信小程序 jscode2session 响应解析失败: {$detail}
wechat-mini-app-error-response = 微信小程序错误 {$code}: {$message}
wechat-mini-app-jscode2session-response-missing-openid = 微信小程序 jscode2session 响应缺少 openid 字段

# --- 支付宝授权登录（alipay）---
alipay-rsa-key-parse-failed = 支付宝 RSA 私钥解析失败: {$detail}
alipay-token-request-failed = 支付宝 token 请求失败: {$detail}
alipay-token-response-parse-failed = 支付宝 token 响应解析失败: {$detail}
alipay-error-response = 支付宝错误 {$code}: {$message}
alipay-response-missing-user-id = 支付宝响应缺少 user_id 字段
alipay-user-info-request-failed = 支付宝用户信息请求失败: {$detail}
alipay-user-info-response-parse-failed = 支付宝用户信息响应解析失败: {$detail}
alipay-response-missing-user-info-share-response = 支付宝响应缺少 alipay_user_info_share_response 字段

# --- Keycloak OIDC RP（keycloak）---
keycloak-http-client-build-failed = 构建 HTTP 客户端失败: {$detail}
keycloak-discovery-request-failed = discovery 请求失败: {$detail}
keycloak-discovery-status-not-2xx = discovery 响应状态码非 2xx: {$detail}
keycloak-discovery-response-parse-failed = discovery 响应解析失败: {$detail}
keycloak-jwks-request-failed = JWKS 请求失败: {$detail}
keycloak-jwks-status-not-2xx = JWKS 响应状态码非 2xx: {$detail}
keycloak-jwks-response-parse-failed = JWKS 响应解析失败: {$detail}
keycloak-id-token-header-parse-failed = id_token header 解析失败: {$detail}
keycloak-id-token-header-missing-kid = id_token header 缺少 kid 字段
keycloak-jwks-key-not-found = JWKS 中未找到 kid={$kid} 的公钥
keycloak-rsa-public-key-build-failed = 构造 RSA 公钥失败: {$detail}
keycloak-token-expired = token 已过期
keycloak-id-token-verify-failed = id_token 验签失败: {$detail}
keycloak-code-empty = code 不可为空
keycloak-public-client-requires-pkce = public client（client_secret=None）必须调用 with_pkce 设置 PKCE verifier
keycloak-exchange-code-request-failed = exchange_code 请求失败: {$detail}
keycloak-exchange-code-status-not-2xx = exchange_code 响应状态码非 2xx: {$detail}
keycloak-exchange-code-response-parse-failed = exchange_code 响应解析失败: {$detail}

# ============================================================================
# DAO 错误（i18n 改造）
# ============================================================================
dao-app-auth-method-create-insert = app_auth_method create 插入失败: {$arg0}
dao-app-auth-method-create-session = app_auth_method create 获取 session 失败: {$arg0}
dao-app-auth-method-delete-delete = app_auth_method delete 删除失败: {$arg0}
dao-app-auth-method-delete-session = app_auth_method delete 获取 session 失败: {$arg0}
dao-app-auth-method-find-by-id-query = app_auth_method find-by-id 查询失败: {$arg0}
dao-app-auth-method-find-by-user-id-query = app_auth_method find-by-user-id 查询失败: {$arg0}
dao-app-auth-method-list-connection = app_auth_method list 获取 connection 失败: {$arg0}
dao-app-auth-method-list-query = app_auth_method list 查询失败: {$arg0}
dao-app-auth-method-list-session = app_auth_method list 获取 session 失败: {$arg0}
dao-app-auth-method-row-parse-create-time = app_auth_method 行解析失败 (create_time): {$arg0}
dao-app-auth-method-row-parse-external-id = app_auth_method 行解析失败 (external_id): {$arg0}
dao-app-auth-method-row-parse-id = app_auth_method 行解析失败 (id): {$arg0}
dao-app-auth-method-row-parse-metadata = app_auth_method 行解析失败 (metadata): {$arg0}
dao-app-auth-method-row-parse-method-type = app_auth_method 行解析失败 (method_type): {$arg0}
dao-app-auth-method-row-parse-tenant-id = app_auth_method 行解析失败 (tenant_id): {$arg0}
dao-app-auth-method-row-parse-user-id = app_auth_method 行解析失败 (user_id): {$arg0}
dao-app-login-log-create-connection = app_login_log create 获取 connection 失败: {$arg0}
dao-app-login-log-create-insert = app_login_log create 插入失败: {$arg0}
dao-app-login-log-create-session = app_login_log create 获取 session 失败: {$arg0}
dao-app-login-log-find-by-id-query = app_login_log find-by-id 查询失败: {$arg0}
dao-app-login-log-find-by-id-session = app_login_log find-by-id 获取 session 失败: {$arg0}
dao-app-login-log-find-by-user-id-query = app_login_log find-by-user-id 查询失败: {$arg0}
dao-app-login-log-list-connection = app_login_log list 获取 connection 失败: {$arg0}
dao-app-login-log-list-query = app_login_log list 查询失败: {$arg0}
dao-app-login-log-list-session = app_login_log list 获取 session 失败: {$arg0}
dao-app-login-log-row-parse-action = app_login_log 行解析失败 (action): {$arg0}
dao-app-login-log-row-parse-create-time = app_login_log 行解析失败 (create_time): {$arg0}
dao-app-login-log-row-parse-device-id = app_login_log 行解析失败 (device_id): {$arg0}
dao-app-login-log-row-parse-fail-reason = app_login_log 行解析失败 (fail_reason): {$arg0}
dao-app-login-log-row-parse-id = app_login_log 行解析失败 (id): {$arg0}
dao-app-login-log-row-parse-ip = app_login_log 行解析失败 (ip): {$arg0}
dao-app-login-log-row-parse-tenant-id = app_login_log 行解析失败 (tenant_id): {$arg0}
dao-app-login-log-row-parse-user-id = app_login_log 行解析失败 (user_id): {$arg0}
dao-app-permission-create-connection = app_permission create 获取 connection 失败: {$arg0}
dao-app-permission-create-insert = app_permission create 插入失败: {$arg0}
dao-app-permission-create-session = app_permission create 获取 session 失败: {$arg0}
dao-app-permission-delete-connection = app_permission delete 获取 connection 失败: {$arg0}
dao-app-permission-delete-delete = app_permission delete 删除失败: {$arg0}
dao-app-permission-delete-session = app_permission delete 获取 session 失败: {$arg0}
dao-app-permission-find-by-code-query = app_permission find-by-code 查询失败: {$arg0}
dao-app-permission-find-by-id-query = app_permission find-by-id 查询失败: {$arg0}
dao-app-permission-list-connection = app_permission list 获取 connection 失败: {$arg0}
dao-app-permission-list-query = app_permission list 查询失败: {$arg0}
dao-app-permission-list-session = app_permission list 获取 session 失败: {$arg0}
dao-app-permission-row-parse-action = app_permission 行解析失败 (action): {$arg0}
dao-app-permission-row-parse-code = app_permission 行解析失败 (code): {$arg0}
dao-app-permission-row-parse-created-at = app_permission 行解析失败 (created_at): {$arg0}
dao-app-permission-row-parse-id = app_permission 行解析失败 (id): {$arg0}
dao-app-permission-row-parse-name = app_permission 行解析失败 (name): {$arg0}
dao-app-permission-row-parse-resource-type = app_permission 行解析失败 (resource_type): {$arg0}
dao-app-permission-row-parse-updated-at = app_permission 行解析失败 (updated_at): {$arg0}
dao-app-permission-update-connection = app_permission update 获取 connection 失败: {$arg0}
dao-app-permission-update-session = app_permission update 获取 session 失败: {$arg0}
dao-app-permission-update-update = app_permission update 更新失败: {$arg0}
dao-app-role-create-connection = app_role create 获取 connection 失败: {$arg0}
dao-app-role-create-insert = app_role create 插入失败: {$arg0}
dao-app-role-create-session = app_role create 获取 session 失败: {$arg0}
dao-app-role-delete-connection = app_role delete 获取 connection 失败: {$arg0}
dao-app-role-delete-delete = app_role delete 删除失败: {$arg0}
dao-app-role-delete-session = app_role delete 获取 session 失败: {$arg0}
dao-app-role-find-by-code-connection = app_role find-by-code 获取 connection 失败: {$arg0}
dao-app-role-find-by-code-query = app_role find-by-code 查询失败: {$arg0}
dao-app-role-find-by-code-session = app_role find-by-code 获取 session 失败: {$arg0}
dao-app-role-find-by-id-connection = app_role find-by-id 获取 connection 失败: {$arg0}
dao-app-role-find-by-id-query = app_role find-by-id 查询失败: {$arg0}
dao-app-role-find-by-id-session = app_role find-by-id 获取 session 失败: {$arg0}
dao-app-role-list-connection = app_role list 获取 connection 失败: {$arg0}
dao-app-role-list-query = app_role list 查询失败: {$arg0}
dao-app-role-list-session = app_role list 获取 session 失败: {$arg0}
dao-app-role-permission-assign-insert = app_role_permission assign 插入失败: {$arg0}
dao-app-role-permission-list-query = app_role_permission list 查询失败: {$arg0}
dao-app-role-permission-list-session = app_role_permission list 获取 session 失败: {$arg0}
dao-app-role-permission-revoke-delete = app_role_permission revoke 删除失败: {$arg0}
dao-app-role-permission-row-parse-role-id = app_role_permission 行解析失败 (role_id): {$arg0}
dao-app-role-permission-row-parse-tenant-id = app_role_permission 行解析失败 (tenant_id): {$arg0}
dao-app-role-row-parse-code = app_role 行解析失败 (code): {$arg0}
dao-app-role-row-parse-created-at = app_role 行解析失败 (created_at): {$arg0}
dao-app-role-row-parse-description = app_role 行解析失败 (description): {$arg0}
dao-app-role-row-parse-id = app_role 行解析失败 (id): {$arg0}
dao-app-role-row-parse-name = app_role 行解析失败 (name): {$arg0}
dao-app-role-row-parse-tenant-id = app_role 行解析失败 (tenant_id): {$arg0}
dao-app-role-row-parse-updated-at = app_role 行解析失败 (updated_at): {$arg0}
dao-app-role-update-connection = app_role update 获取 connection 失败: {$arg0}
dao-app-role-update-session = app_role update 获取 session 失败: {$arg0}
dao-app-role-update-update = app_role update 更新失败: {$arg0}
dao-app-session-create-connection = app_session create 获取 connection 失败: {$arg0}
dao-app-session-create-insert = app_session create 插入失败: {$arg0}
dao-app-session-create-session = app_session create 获取 session 失败: {$arg0}
dao-app-session-delete-connection = app_session delete 获取 connection 失败: {$arg0}
dao-app-session-delete-delete = app_session delete 删除失败: {$arg0}
dao-app-session-delete-session = app_session delete 获取 session 失败: {$arg0}
dao-app-session-find-by-session-id-query = app_session find-by-session-id 查询失败: {$arg0}
dao-app-session-find-by-user-id-query = app_session find-by-user-id 查询失败: {$arg0}
dao-app-session-list-connection = app_session list 获取 connection 失败: {$arg0}
dao-app-session-list-query = app_session list 查询失败: {$arg0}
dao-app-session-list-session = app_session list 获取 session 失败: {$arg0}
dao-app-session-row-parse-device-id = app_session 行解析失败 (device_id): {$arg0}
dao-app-session-row-parse-expire-time = app_session 行解析失败 (expire_time): {$arg0}
dao-app-session-row-parse-ip = app_session 行解析失败 (ip): {$arg0}
dao-app-session-row-parse-last-active = app_session 行解析失败 (last_active): {$arg0}
dao-app-session-row-parse-login-time = app_session 行解析失败 (login_time): {$arg0}
dao-app-session-row-parse-session-id = app_session 行解析失败 (session_id): {$arg0}
dao-app-session-row-parse-tenant-id = app_session 行解析失败 (tenant_id): {$arg0}
dao-app-session-row-parse-user-agent = app_session 行解析失败 (user_agent): {$arg0}
dao-app-session-row-parse-user-id = app_session 行解析失败 (user_id): {$arg0}
dao-app-session-update-last-active-update = app_session update-last-active 更新失败: {$arg0}
dao-app-user-create-connection = app_user create 获取 connection 失败: {$arg0}
dao-app-user-create-insert = app_user create 插入失败: {$arg0}
dao-app-user-create-session = app_user create 获取 session 失败: {$arg0}
dao-app-user-delete-connection = app_user delete 获取 connection 失败: {$arg0}
dao-app-user-delete-delete = app_user delete 删除失败: {$arg0}
dao-app-user-delete-session = app_user delete 获取 session 失败: {$arg0}
dao-app-user-device-block-update = app_user_device block 更新失败: {$arg0}
dao-app-user-device-count-connection = app_user_device count 获取 connection 失败: {$arg0}
dao-app-user-device-count-empty = app_user_device COUNT(*) 未返回行: {$arg0}
dao-app-user-device-count-query = app_user_device count 查询失败: {$arg0}
dao-app-user-device-count-session = app_user_device count 获取 session 失败: {$arg0}
dao-app-user-device-insert = app_user_device 插入失败: {$arg0}
dao-app-user-device-list-connection = app_user_device list 获取 connection 失败: {$arg0}
dao-app-user-device-list-query = app_user_device list 查询失败: {$arg0}
dao-app-user-device-list-session = app_user_device list 获取 session 失败: {$arg0}
dao-app-user-device-parse-count = app_user_device 解析 count 失败: {$arg0}
dao-app-user-device-parse-exists-id = app_user_device 解析已存在 id 失败: {$arg0}
dao-app-user-device-query-exists = app_user_device 查询已存在失败: {$arg0}
dao-app-user-device-row-parse-created-at = app_user_device 行解析失败 (created_at): {$arg0}
dao-app-user-device-row-parse-device-name = app_user_device 行解析失败 (device_name): {$arg0}
dao-app-user-device-row-parse-id = app_user_device 行解析失败 (id): {$arg0}
dao-app-user-device-row-parse-last-seen-at = app_user_device 行解析失败 (last_seen_at): {$arg0}
dao-app-user-device-row-parse-login-id = app_user_device 行解析失败 (login_id): {$arg0}
dao-app-user-device-row-parse-tenant-id = app_user_device 行解析失败 (tenant_id): {$arg0}
dao-app-user-device-row-parse-user-agent = app_user_device 行解析失败 (user_agent): {$arg0}
dao-app-user-device-unblock-update = app_user_device unblock 更新失败: {$arg0}
dao-app-user-device-update-last-seen-at = app_user_device 更新 last_seen_at 失败: {$arg0}
dao-app-user-ext-delete-connection = app_user_ext delete 获取 connection 失败: {$arg0}
dao-app-user-ext-delete-delete = app_user_ext delete 删除失败: {$arg0}
dao-app-user-ext-delete-session = app_user_ext delete 获取 session 失败: {$arg0}
dao-app-user-ext-find-by-user-and-key-query = app_user_ext find-by-user-and-key 查询失败: {$arg0}
dao-app-user-ext-find-by-user-id-query = app_user_ext find-by-user-id 查询失败: {$arg0}
dao-app-user-ext-list-connection = app_user_ext list 获取 connection 失败: {$arg0}
dao-app-user-ext-list-query = app_user_ext list 查询失败: {$arg0}
dao-app-user-ext-list-session = app_user_ext list 获取 session 失败: {$arg0}
dao-app-user-ext-row-parse-created-at = app_user_ext 行解析失败 (created_at): {$arg0}
dao-app-user-ext-row-parse-field-key = app_user_ext 行解析失败 (field_key): {$arg0}
dao-app-user-ext-row-parse-field-type = app_user_ext 行解析失败 (field_type): {$arg0}
dao-app-user-ext-row-parse-field-value = app_user_ext 行解析失败 (field_value): {$arg0}
dao-app-user-ext-row-parse-id = app_user_ext 行解析失败 (id): {$arg0}
dao-app-user-ext-row-parse-tenant-id = app_user_ext 行解析失败 (tenant_id): {$arg0}
dao-app-user-ext-row-parse-updated-at = app_user_ext 行解析失败 (updated_at): {$arg0}
dao-app-user-ext-row-parse-user-id = app_user_ext 行解析失败 (user_id): {$arg0}
dao-app-user-ext-upsert = app_user_ext upsert: {$arg0}
dao-app-user-ext-upsert-connection = app_user_ext upsert 获取 connection 失败: {$arg0}
dao-app-user-ext-upsert-session = app_user_ext upsert 获取 session 失败: {$arg0}
dao-app-user-find-by-id-connection = app_user find-by-id 获取 connection 失败: {$arg0}
dao-app-user-find-by-id-query = app_user find-by-id 查询失败: {$arg0}
dao-app-user-find-by-id-session = app_user find-by-id 获取 session 失败: {$arg0}
dao-app-user-find-by-username-query = app_user find-by-username 查询失败: {$arg0}
dao-app-user-list-connection = app_user list 获取 connection 失败: {$arg0}
dao-app-user-list-query = app_user list 查询失败: {$arg0}
dao-app-user-list-session = app_user list 获取 session 失败: {$arg0}
dao-app-user-role-assign-connection = app_user_role assign 获取 connection 失败: {$arg0}
dao-app-user-role-assign-insert = app_user_role assign 插入失败: {$arg0}
dao-app-user-role-assign-session = app_user_role assign 获取 session 失败: {$arg0}
dao-app-user-role-find-by-role-id-query = app_user_role find-by-role-id 查询失败: {$arg0}
dao-app-user-role-find-by-user-id-query = app_user_role find-by-user-id 查询失败: {$arg0}
dao-app-user-role-list-connection = app_user_role list 获取 connection 失败: {$arg0}
dao-app-user-role-list-query = app_user_role list 查询失败: {$arg0}
dao-app-user-role-list-session = app_user_role list 获取 session 失败: {$arg0}
dao-app-user-role-revoke-connection = app_user_role revoke 获取 connection 失败: {$arg0}
dao-app-user-role-revoke-delete = app_user_role revoke 删除失败: {$arg0}
dao-app-user-role-revoke-session = app_user_role revoke 获取 session 失败: {$arg0}
dao-app-user-role-row-parse-grant-time = app_user_role 行解析失败 (grant_time): {$arg0}
dao-app-user-role-row-parse-role-id = app_user_role 行解析失败 (role_id): {$arg0}
dao-app-user-role-row-parse-scope = app_user_role 行解析失败 (scope): {$arg0}
dao-app-user-role-row-parse-tenant-id = app_user_role 行解析失败 (tenant_id): {$arg0}
dao-app-user-role-row-parse-user-id = app_user_role 行解析失败 (user_id): {$arg0}
dao-app-user-row-parse-created-at = app_user 行解析失败 (created_at): {$arg0}
dao-app-user-row-parse-id = app_user 行解析失败 (id): {$arg0}
dao-app-user-row-parse-last-login-at = app_user 行解析失败 (last_login_at): {$arg0}
dao-app-user-row-parse-password-hash = app_user 行解析失败 (password_hash): {$arg0}
dao-app-user-row-parse-status = app_user 行解析失败 (status): {$arg0}
dao-app-user-row-parse-tenant-id = app_user 行解析失败 (tenant_id): {$arg0}
dao-app-user-row-parse-updated-at = app_user 行解析失败 (updated_at): {$arg0}
dao-app-user-row-parse-username = app_user 行解析失败 (username): {$arg0}
dao-app-user-update-connection = app_user update 获取 connection 失败: {$arg0}
dao-app-user-update-session = app_user update 获取 session 失败: {$arg0}
dao-app-user-update-update = app_user update 更新失败: {$arg0}
dao-child-role-read = child_role 读取失败: {$arg0}
dao-dbnexus-init = dbnexus 初始化失败: {$arg0}
dao-dbnexus-migrate = dbnexus 迁移失败 ({$arg0}): {$arg1}
dao-incr-parse-u64 = incr: 现存值非 u64，key={$arg0}, value={$arg1}
dao-key-missing = 键不存在: {$arg0}
dao-oxcache-delete-sync = oxcache delete_sync 失败: {$arg0}
dao-oxcache-exists-sync = oxcache exists_sync 失败: {$arg0}
dao-oxcache-expire-set-with-ttl-sync = oxcache expire (set_with_ttl_sync) 失败: {$arg0}
dao-oxcache-expire-sync = oxcache expire_sync 失败: {$arg0}
dao-oxcache-get-sync = oxcache get_sync 失败: {$arg0}
dao-oxcache-init = oxcache 初始化失败: {$arg0}
dao-oxcache-set-with-ttl-sync = oxcache set_with_ttl_sync 失败: {$arg0}
dao-oxcache-ttl-sync = oxcache ttl_sync 失败: {$arg0}
dao-oxcache-update-set-with-ttl-sync = oxcache update (set_with_ttl_sync) 失败: {$arg0}
dao-parent-role-read = parent_role 读取失败: {$arg0}
dao-role-closure-serialize = role_closure 序列化失败: {$arg0}
dao-role-hierarchy-add-edge-insert = role_hierarchy add_edge 插入失败: {$arg0}
dao-role-hierarchy-add-edge-session = role_hierarchy add_edge 获取 session 失败: {$arg0}
dao-role-hierarchy-connection = role_hierarchy 获取 connection 失败: {$arg0}
dao-role-hierarchy-query = role_hierarchy 查询失败: {$arg0}
dao-role-hierarchy-session = role_hierarchy 获取 session 失败: {$arg0}

# Protocol 错误（i18n 改造）

# apikey
apikey-clock = 获取系统时间失败: {$arg0}
apikey-serialize = 序列化 ApiKeyInfo 失败: {$arg0}
apikey-deserialize = 反序列化 ApiKeyInfo 失败: {$arg0}
apikey-namespace-empty = namespace 不能为空
apikey-timeout-positive = timeout 必须大于 0
apikey-not-found = API Key 不存在
apikey-revoked = API Key 已吊销
apikey-expired = API Key 已过期

# jwt
jwt-secret-empty = JWT secret 不能为空
jwt-sign = JWT 签发失败: {$arg0}
jwt-expired = JWT 已过期: {$arg0}
jwt-not-yet-valid = JWT 未生效（nbf 校验失败）: {$arg0}
jwt-invalid = JWT 校验失败: {$arg0}
jwt-refresh-get-session = refresh_tokens 获取 session 失败: {$arg0}
jwt-refresh-get-conn = refresh_tokens 获取 connection 失败: {$arg0}
jwt-refresh-query = refresh_tokens 查询失败 / 字段读取失败: {$arg0}
jwt-refresh-insert = refresh_tokens INSERT 失败: {$arg0}
jwt-refresh-update = refresh_tokens UPDATE 失败: {$arg0}
jwt-refresh-select-child = refresh_tokens 查询子代失败: {$arg0}

# sso / oidc / saml
sso-oidc-http-client-build = 构建 HTTP 客户端失败: {$arg0}
sso-oidc-body-read = 读取响应体失败: {$arg0}
sso-oidc-body-utf8 = 响应体 UTF-8 解码失败: {$arg0}
sso-oidc-jwks-request = OIDC JWKS 请求失败: {$arg0}
sso-oidc-jwks-body-read = OIDC JWKS 响应体读取失败: {$arg0}
sso-oidc-jwks-parse = OIDC JWKS 响应解析 / 反序列化失败: {$arg0}
sso-oidc-jwks-serialize = OIDC JWKS 序列化失败: {$arg0}
sso-oidc-token-exchange = OIDC token 交换失败: {$arg0}
sso-oidc-token-body-read = OIDC token 响应体读取失败: {$arg0}
sso-oidc-token-parse = OIDC token 响应解析失败: {$arg0}
sso-oidc-userinfo-request = OIDC userinfo 请求失败: {$arg0}
sso-oidc-userinfo-body-read = OIDC userinfo 响应体读取失败: {$arg0}
sso-oidc-userinfo-parse = OIDC userinfo 响应解析失败: {$arg0}
sso-oidc-id-token-header-parse = OIDC id_token header 解析失败: {$arg0}
sso-oidc-id-token-header-missing-kid = OIDC id_token header 缺少 kid 字段
sso-oidc-jwks-key-not-found = OIDC JWKS 中未找到 kid={$arg0} 的公钥
sso-oidc-rsa-build = OIDC 构造 RSA 公钥失败: {$arg0}
sso-oidc-id-token-verify = OIDC id_token 验签失败: {$arg0}
sso-oidc-id-token-expired = OIDC id_token 已过期
sso-oidc-id-token-invalid = OIDC id_token 校验失败（期望 {$arg0}，实际 {$arg1}）
sso-oidc-missing-id-token = OIDC token 响应中缺少 id_token
sso-ticket-hmac-init = HMAC 密钥初始化失败: {$arg0}
sso-ticket-serialize = 序列化 SSO ticket 失败: {$arg0}
sso-ticket-read = SSO ticket 读取失败: {$arg0}
sso-ticket-deserialize = 反序列化 SSO ticket 失败: {$arg0}
sso-ticket-atomic-consume = SSO ticket 原子消费失败: {$arg0}
sso-ticket-format-no-sig = SSO ticket 格式错误：缺少签名部分
sso-ticket-sig-verify = SSO ticket 签名验证失败：可能被篡改或伪造
sso-ticket-missing-or-expired = SSO 票据不存在或已过期
sso-saml-xml-parse = SAML XML 解析失败: {$arg0}
sso-saml-not-on-or-after-parse = SAML NotOnOrAfter 解析失败: {$arg0}
sso-redis-publish = Redis PUBLISH 失败: {$arg0}

# oauth2 client
oauth2-http-client-build = 构建 HTTP 客户端失败: {$arg0}
oauth2-body-read = 读取响应体失败: {$arg0}
oauth2-body-utf8 = 响应体 UTF-8 解码失败: {$arg0}
oauth2-token-endpoint = 请求 token 端点失败: {$arg0}
oauth2-introspect-endpoint = 请求 introspect 端点失败: {$arg0}
oauth2-client-id-empty = client_id 不可为空
oauth2-client-secret-empty = OIDC secret 不能为空
oauth2-username-empty = username 不可为空
oauth2-body-overflow = 响应体长度溢出（E2）
oauth2-token-body-read = 读取 token 响应体失败: {$arg0}
oauth2-token-body-parse = 解析 token 响应失败: {$arg0}
oauth2-introspect-body-read = 读取 introspection 响应体失败: {$arg0}
oauth2-introspect-body-parse = 解析 introspection 响应失败: {$arg0}

# sign
sign-app-key-empty = app_key 不可为空
sign-timestamp-window = 签名时间戳超出窗口
sign-nonce-replay = nonce 重放
sign-mismatch = 签名不匹配
sign-base64-decode = 签名 Base64 解码失败: {$arg0}
sign-clock = 获取系统时间失败: {$arg0}

# system clock (generic)
system-clock-error = 系统时间错误: {$arg0}

# social dao
dao-social-binding-get-session = social_binding 获取 session 失败: {$arg0}
dao-social-binding-get-conn = social_binding 获取 connection 失败: {$arg0}
dao-social-binding-query = social_binding 查询失败: {$arg0}
dao-social-binding-login-id-read = login_id 读取失败: {$arg0}
dao-social-binding-insert-select = INSERT/SELECT login_id 失败: {$arg0}
dao-key-not-found = DAO 键不存在: {$arg0}

# oauth2_server
oauth2-server-authorize-serialize = AuthorizationCode 序列化失败: {$arg0}
oauth2-server-authorize-deserialize = AuthorizationCode 反序列化失败: {$arg0}
oauth2-server-token-serialize = TokenRecord 序列化失败: {$arg0}
oauth2-server-token-deserialize = TokenRecord 反序列化失败: {$arg0}
oauth2-server-token-invalid-client = invalid_client: {$arg0} 不存在
oauth2-server-client-serialize = OAuth2Client 序列化失败: {$arg0}
oauth2-server-client-deserialize = OAuth2Client 反序列化失败: {$arg0}
oauth2-server-client-hash = Argon2 哈希失败: {$arg0}
oauth2-server-client-hash-format = Argon2 哈希格式无效: {$arg0}
oauth2-server-introspect-invalid-client = invalid_client: {$arg0} 不存在
oauth2-server-revoke-invalid-client = invalid_client: {$arg0} 不存在

# Strategy/Web/Context/Backend 等错误（i18n 改造）
strategy-limiter-storage = 限流器存储错误: {$arg0}
strategy-system-time = 系统时间错误: {$arg0}
strategy-limiteron-op = limiteron 操作失败: {$arg0}
strategy-ddos-global = DDoS 全局限流器错误: {$arg0}
strategy-ddos-ip = DDoS IP {$arg0} 限流器错误
strategy-ban-is-banned = ban_storage is_banned 失败: {$arg0}
strategy-incr-ttl = limiter incr_with_ttl 失败: {$arg0}
strategy-ban-save = ban_storage save 失败: {$arg0}
strategy-interval-secs-zero = interval_secs 不能为 0
strategy-burst-threshold-zero = burst_threshold 不能为 0
strategy-max-scan-zero = max_scan 不能为 0
strategy-login-id-empty = login_id 不能为空
strategy-perm-empty = 权限字符串不能为空
strategy-role-empty = 角色字符串不能为空
strategy-maxmind-open = MaxMindDb 打开文件失败 {$arg0}
strategy-maxmind-from-bytes = MaxMindDb 从字节构造失败: {$arg0}
strategy-invalid-ip = 无效的 IP 地址: {$arg0}
strategy-maxmind-query = MaxMindDb 查询失败 (IP={$arg0})
strategy-anomalous-serialize = 序列化登录记录失败: {$arg0}
strategy-analyzer-panic = 分析器任务 panic: {$arg0}
strategy-alert-serialize = 序列化 SecurityAlertEvent 为 JSON 失败: {$arg0}
web-not-login = 未登录
web-token-invalid = token 无效或会话不存在
web-key-not-found = 键不存在: {$arg0}
ctx-tenant-context-missing = 无租户上下文，租户隔离校验失败
ctx-tenant-id-invalid = X-Tenant-Id 不是合法的 i64: {$arg0}
backend-http-client-build = 构建 HTTP 客户端失败: {$arg0}
backend-http-request = HTTP 请求失败: {$arg0}
backend-response-deser = 响应反序列化失败: {$arg0}
backend-api-error = API 错误 [{$arg0}]
backend-ca-load = 加载 CA 证书失败: {$arg0}
backend-client-cert-load = 加载客户端证书失败: {$arg0}
backend-token-invalid-or-expired = token 无效或已过期
backend-auth-logic-not-injected = auth_logic 未注入，switch_to 不可用
abac-expr-empty = abac_expr 不能为空
abac-cedar-schema-parse = Cedar schema 解析失败: {$arg0}
abac-decision-cache-init = oxcache 决策缓存初始化失败: {$arg0}
abac-decision-cache-read = 决策缓存读取失败: {$arg0}
abac-principal-parse = principal 解析失败: {$arg0}
abac-action-parse = action 解析失败: {$arg0}
abac-resource-parse = resource 解析失败: {$arg0}
abac-context-parse = context 解析失败: {$arg0}
abac-cedar-request-build = Cedar Request 构造失败: {$arg0}
abac-decision-cache-write = 决策缓存写入失败: {$arg0}
abac-cedar-policy-parse = Cedar 策略解析失败: {$arg0}
abac-cedar-policy-add = Cedar 策略添加失败: {$arg0}
abac-decision-cache-clear = 决策缓存清空失败: {$arg0}
abac-cedar-policy-delete = Cedar 策略删除失败: {$arg0}
abac-cedar-policy-parse-id = Cedar 策略 {$arg0} 解析失败: {$arg1}
abac-cedar-policy-add-id = Cedar 策略 {$arg0} 添加失败: {$arg1}
abac-temp-cedar-policy-parse = 临时 Cedar 策略解析失败: {$arg0}
abac-temp-cedar-policy-add = 临时 Cedar 策略添加失败: {$arg0}
manager-not-init = BulwarkManager 未初始化
manager-timeout-overflow = timeout 溢出 u64: {$arg0}
router-not-login = 未登录
router-key-not-found = 键不存在: {$arg0}
server-token-empty = token 为空
server-no-permission = 无权限
server-apikey-invalid = API Key 无效
server-external-tls-load = 加载外网 TLS 配置失败: {$arg0}
server-external-addr-parse = 外网地址解析失败: {$arg0}
server-external-server-error = 外网服务器异常: {$arg0}
server-external-bind = 绑定外网端口失败: {$arg0}
server-external-task-panic = 外网 task panic: {$arg0}
server-internal-tls-load = 加载内网 TLS 配置失败: {$arg0}
server-internal-addr-parse = 内网地址解析失败: {$arg0}
server-internal-server-error = 内网服务器异常: {$arg0}
server-internal-bind = 绑定内网端口失败: {$arg0}
server-internal-task-panic = 内网 task panic: {$arg0}
plugin-on-login-failed = on_login 失败
plugin-on-logout-failed = on_logout 失败
listener-on-event-failed = on_event 失败
listener-signing-key-not-config = signing_key 未配置，无法导出签名链
listener-get-session = get_session 失败: {$arg0}
listener-connection = connection 失败: {$arg0}
listener-audit-insert = INSERT audit_logs 失败: {$arg0}
listener-audit-select = SELECT audit_logs 失败: {$arg0}
listener-audit-parse-tenant-id = audit_logs 行解析失败 (tenant_id): {$arg0}
listener-audit-parse-event-type = audit_logs 行解析失败 (event_type): {$arg0}
listener-audit-parse-login-id = audit_logs 行解析失败 (login_id): {$arg0}
listener-audit-parse-token = audit_logs 行解析失败 (token): {$arg0}
listener-audit-parse-ip = audit_logs 行解析失败 (ip): {$arg0}
listener-audit-parse-user-agent = audit_logs 行解析失败 (user_agent): {$arg0}
listener-audit-parse-metadata = audit_logs 行解析失败 (metadata): {$arg0}
listener-audit-parse-success = audit_logs 行解析失败 (success): {$arg0}
listener-audit-parse-created-at = audit_logs 行解析失败 (created_at): {$arg0}
listener-json-serialize = JSON 序列化失败: {$arg0}
listener-hmac-key-invalid = HMAC key 无效: {$arg0}
limiter-eval-lua-empty = eval_lua 返回空结果
cache-l1-get = oxcache L1 get 失败: {$arg0}
cache-l1-perm-deser = L1 权限缓存反序列化失败: {$arg0}
cache-l1-role-deser = L1 角色缓存反序列化失败: {$arg0}
cache-l2-perm-deser = L2 权限缓存反序列化失败: {$arg0}
cache-l2-role-deser = L2 角色缓存反序列化失败: {$arg0}
cache-perm-serialize = 权限列表序列化失败: {$arg0}
cache-role-serialize = 角色列表序列化失败: {$arg0}
cache-l1-set = oxcache L1 set_with_ttl 失败: {$arg0}
cache-l1-delete = oxcache L1 delete 失败: {$arg0}
json-serialize = JSON 序列化失败: {$arg0}
json-deserialize = JSON 反序列化失败: {$arg0}
json-template-parse = JSON 模板解析失败: {$arg0}

# Stp/Session/Core/Secure/Annotation/Account 错误（i18n 改造）
stp-dao-find-by-id = 键不存在: {$arg0}
stp-token-not-found = token 不存在: {$arg0}
stp-token-invalid = token 无效
stp-no-api-key = 未提供 API Key
stp-login-id-empty = login_id 不能为空
stp-token-empty = token 不能为空
stp-token-control-char = token 含控制字符
stp-not-login = 未登录
stp-session-timeout = 会话悬停超时
stp-dao-connect = 权限数据源故障
stp-context-not-set = 未设置当前请求上下文（未调用 with_current_token）
secure-totp-init = TOTP 初始化失败: {$arg0}
secure-base32-decode = Base32 解码失败: {$arg0}
secure-base64-decode = Base64 解码失败: {$arg0}
secure-utf8-decode = UTF-8 解码失败: {$arg0}
secure-cred-missing-colon = 凭证格式错误：缺失冒号分隔符
secure-auth-header-no-cred = Authorization header 格式错误：缺少凭证部分
secure-http-digest-no-params = Authorization header 格式错误：缺少参数部分
secure-http-digest-missing-nonce = 缺失 nonce 参数
secure-http-digest-missing-response = 缺失 response 参数
secure-http-digest-missing-nc = 缺失 nc 参数
secure-http-digest-missing-cnonce = 缺失 cnonce 参数
secure-sms-code-wrong = 验证码错误
secure-phone-empty = phone 不能为空
secure-counter-parse = 计数器值解析失败 key={$arg0}: {$arg1}
secure-system-time = 系统时间错误: {$arg0}
secure-limiter-incr = limiteron incr_with_ttl 失败: {$arg0}
core-token-invalid-or-expired = token 无效或已过期
core-not-login = token 无效或已过期
core-hmac-key-invalid = HMAC 密钥长度无效: {$arg0}
core-simple-token-no-hmac-sep = Simple token 格式错误：缺少 '.' HMAC 分隔符
core-simple-token-no-dash-sep = Simple token 格式错误：缺少 '-' 分隔符
core-perm-empty = 权限字符串不能为空
core-role-empty = 角色字符串不能为空
session-sim-token-serialize = 序列化 TokenSession 失败: {$arg0}
session-sim-token-deserialize = 反序列化 TokenSession 失败: {$arg0}
session-sim-account-deserialize = 反序列化 AccountSession 失败: {$arg0}
session-account-not-found = AccountSession 不存在: {$arg0}
session-sim-account-serialize = 序列化 AccountSession 失败: {$arg0}
session-token-not-found = token 不存在: {$arg0}
session-token-empty = token 不能为空
session-token-too-long = token 长度超限
session-sim-anon-deserialize = 反序列化匿名 TokenSession 失败: {$arg0}
session-sim-anon-serialize = 序列化匿名 TokenSession 失败: {$arg0}
session-mock-callback = 模拟回调失败
annotation-not-login = 未登录
annotation-no-token = 未提供 token
annotation-token-invalid = token 无效或会话不存在
annotation-tenant-id-invalid = X-Tenant-Id 不是合法的 i64: {$arg0}
account-argon2-param = Argon2 参数无效: {$arg0}
account-argon2-hash = Argon2 哈希失败: {$arg0}
account-argon2-format = Argon2 哈希格式无效: {$arg0}
account-argon2-verify = Argon2 校验失败: {$arg0}
account-bcrypt-hash = Bcrypt 哈希失败: {$arg0}
account-bcrypt-format = Bcrypt 哈希格式无效: {$arg0}
account-backup-serialize = backup_code secret_data 序列化失败: {$arg0}
account-cred-deserialize = CredentialModel 反序列化失败: {$arg0}
account-cred-serialize = CredentialModel 序列化失败: {$arg0}
account-lockout-deserialize = 反序列化 LockoutState 失败: {$arg0}
account-lockout-serialize = 序列化 LockoutState 失败: {$arg0}
account-disable-serialize = 序列化 DisableEntry 为 JSON 失败: {$arg0}
account-disable-deserialize = 反序列化 DisableEntry 失败: {$arg0}

stp-token-invalid-or-not-login = token 无效或未登录
stp-token-invalid-or-no-login-id = token 无效或不包含 login_id

# ============================================================================
# i18n 迁移补全（2026-07-18）
# ============================================================================

# --- session mock ---
session-mock-delete-failed = mock delete 失败: {$arg0}
session-mock-read-failed = mock read 失败: {$arg0}
session-mock-update-failed = mock update 失败: {$arg0}

# --- sso 补全 ---
sso-mock-key-not-found = key 不存在
sso-oidc-token-status-error = token exchange 响应状态错误: {$arg0}
sso-oidc-userinfo-status-error = userinfo 响应状态错误: {$arg0}
sso-oidc-validate-not-implemented = OIDC id_token 验证未实现
sso-ticket-client-id-mismatch = SSO ticket client_id 不匹配: 期望 {$arg0}, 实际 {$arg1}
sso-ticket-consumed-by-concurrent = SSO ticket 被并发消费
sso-saml-signature-not-implemented = SAML 签名验证未实现
sso-saml-assertion-expired = SAML assertion 已过期: {$arg0}

# --- sign / apikey 补全 ---
sign-app-secret-too-short = app_secret 长度不足: 当前 {$arg0} 字节, 要求至少 {$arg1} 字节 (256 位)
apikey-namespace-too-long = namespace 长度不能超过 64 字符, 实际: {$arg0}
apikey-namespace-invalid-chars = namespace 仅允许 [a-zA-Z0-9_-], 实际: {$arg0}
apikey-namespace-mismatch = API Key namespace 不匹配: 期望 {$arg0}, 实际 {$arg1}
apikey-expired-cannot-rotate = API Key 已过期, 无法轮换

# --- keycloak 补全 ---
keycloak-discovery-body-read-failed = discovery 响应体读取失败: {$detail}
keycloak-dao-not-injected = KeycloakProvider 未注入 DAO, 无法缓存 JWKS (调用 with_dao 注入 BulwarkDao)
keycloak-jwks-body-read-failed = JWKS 响应体读取失败: {$detail}
keycloak-jwks-serialize-failed = JWKS 序列化失败: {$detail}
keycloak-jwks-cache-miss-after-fetch = fetch_jwks 后缓存仍为空 (DAO 写入异常)
keycloak-jwks-deserialize-failed = JWKS 反序列化失败: {$detail}
keycloak-token-immature = token 尚未生效 (nbf 校验失败)
keycloak-token-invalid-audience = token audience 无效
keycloak-token-invalid-issuer = token issuer 无效
keycloak-exchange-code-body-read-failed = exchange_code 响应体读取失败: {$detail}

# --- server / backend 补全 ---
server-caller-not-owner-kickout = caller 非属主且无 admin:sessions 权限, 禁止 kickout
server-caller-not-owner-switch-to = caller 非属主且无 admin:sessions 权限, 禁止 switch_to
backend-auth-logic-not-injected-renew = auth_logic 未注入, renew_to_equivalent 不可用

# --- oauth2_server 补全 ---
oauth2-server-client-invalid-scope = client 不允许请求 scope: {$arg0}
oauth2-server-client-exists = client 已存在: {$arg0}
oauth2-server-client-not-found = client 不存在: {$arg0}
oauth2-server-token-rate-limited-client = client 限速超出: {$arg0}
oauth2-server-token-invalid-client-missing = invalid_client: client_id 缺失
oauth2-server-token-invalid-client-secret = invalid_client: client_secret 错误
oauth2-server-token-unauthorized-auth-code = unauthorized: authorization code 无效或已过期
oauth2-server-token-unauthorized-refresh = unauthorized: refresh token 无效或已过期
oauth2-server-token-invalid-grant-refresh-mismatch = invalid_grant: refresh token 与 client 不匹配
oauth2-server-token-unauthorized-client-credentials = unauthorized: client credentials 无效
oauth2-server-token-unauthorized-password = unauthorized: 用户名或密码错误
oauth2-server-token-unauthorized-grant-no-verifier = unauthorized: 缺少 code_verifier
oauth2-server-token-rate-limited-username = username 限速超出: {$arg0}
oauth2-server-token-rate-limited-locked = account locked: {$arg0}
oauth2-server-token-invalid-grant-credentials = invalid_grant: 凭证无效
oauth2-server-authorize-unsupported-response-type = unsupported response_type: {$arg0}
oauth2-server-authorize-unsupported-code-challenge-method = unsupported code_challenge_method: {$arg0}
oauth2-server-authorize-code-challenge-empty = code_challenge 不能为空
oauth2-server-authorize-redirect-uri-not-allowed = redirect_uri 不被允许: {$arg0}
oauth2-server-authorize-code-verifier-invalid-length = code_verifier 长度无效
oauth2-server-introspect-invalid-client-secret = invalid_client: client_secret 错误
oauth2-server-revoke-invalid-client-secret = invalid_client: client_secret 错误

# --- account 补全 ---
account-password-unsupported-hash-format = 不支持的哈希格式: {$arg0}
account-backup-deserialize = backup_code secret_data 反序列化失败: {$arg0}

# ============================================================================
# Stp 层错误（i18n 改造 - session.rs 硬编码中文迁移）
# ============================================================================

# --- SessionLogic trait 默认实现 + BulwarkLogicDefault impl ---
stp-revoke-all-sessions-not-implemented = revoke_all_sessions 需 BulwarkLogicDefault 实现
stp-get-active-sessions-not-implemented = get_active_sessions 需 BulwarkLogicDefault 实现
stp-login-by-token-feature-required = login_by_token 需启用 protocol-oauth2 或 protocol-sso feature
stp-refresh-access-token-not-implemented-db = refresh_access_token 未实现：需启用 db-sqlite feature 并注入 RefreshTokenRotation
stp-refresh-access-token-no-rotation = refresh_access_token 未注入 RefreshTokenRotation
stp-refresh-access-token-feature-required = refresh_access_token 需启用 protocol-jwt + db-sqlite feature

# --- validate_login_with_token_inputs 输入校验 ---
stp-token-length-too-short = token 长度不足: {$arg0} < 8
stp-token-length-too-long = token 长度超限: {$arg0} > 256

# --- login_inner NewDevice 模式 ---
stp-new-device-login-rejected-not-allowed = 新设备登录被拒绝：当前为 NewDevice 模式，不允许新设备登录

# --- check_login_stateless / token_style feature 校验 ---
stp-jwt-token-style-requires-protocol-jwt = jwt token_style 需启用 protocol-jwt feature
stp-stateless-requires-jwt-token-style = Stateless 模式要求 token_style=jwt
stp-stateless-requires-protocol-jwt = Stateless 模式要求启用 protocol-jwt feature
stp-unknown-token-style = 不支持的 token_style: {$arg0}

# --- auto_renewal 续签配置校验 ---
stp-auto-renewal-no-auth-logic = auto_renewal_threshold 启用但 auth_logic 未注入，无法续签
stp-auto-renewal-jwt-requires-protocol-jwt = auto_renewal_threshold 启用且 token_style=jwt，但未启用 protocol-jwt feature

# --- MockAnomalyDetector 失败模拟 ---
stp-mock-login-detection-failed = mock login detection 失败
stp-mock-check-login-detection-failed = mock check_login detection 失败

# ============================================================================
# response_parts 专用 message keys（不含 detail，用于 HTTP 响应体）
# ============================================================================
# 这些 key 用于 BulwarkError::response_parts_i18n() 方法，返回不含变体 detail
# 的通用描述，避免泄露敏感信息（与 response_parts() 的 &'static str 一一对应）。
not-login-msg = 未登录
not-permission-msg = 无权限
not-role-msg = 无角色
invalid-token-msg = Token 无效
token-revoked-msg = Token 已吊销
expired-token-msg = Token 已过期
dao-msg = 数据访问错误
config-msg = 配置错误
internal-msg = 内部错误
session-msg = 会话错误
annotation-msg = 注解错误
context-msg = 上下文错误
oauth2-msg = OAuth2 错误
network-msg = 网络错误
invalid-param-msg = 参数无效
not-implemented-msg = 未实现
firewall-blocked-msg = 防火墙拦截
disable-service-msg = 账号已被封禁
not-safe-msg = 未完成二次认证
invalid-state-transition-msg = 非法状态转换
sms-rate-limit-exceeded-msg = 短信发送频繁
sms-verify-max-attempts-msg = 验证码尝试次数超限
sms-code-not-found-msg = 验证码不存在或已过期
sms-channel-recycled-msg = 短信通道已回收
# Exception 变体依据 code 字段映射的 message
exception-not-login-msg = 未登录
exception-not-permission-msg = 无权限
exception-default-msg = 业务异常
