# Garrison 异常消息中文翻译（默认语言）
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
invalid-response = 上游响应无效: {$detail}
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

# 邮箱验证码限速异常（email-verification）
email-rate-limit-exceeded = 邮箱限速超出: {$window} 窗口
email-verify-max-attempts = 邮箱验证码尝试次数超限
email-code-not-found = 邮箱验证码不存在
email-channel-recycled = 邮箱通道已回收

# Credit 计量不足（multi-tenant-credit-metering）
credit-insufficient = Credit 不足: tenant={$tenant_id}, requested={$requested}, remaining={$remaining}

# 0.6.1 缺失基础 key（I18N-KEY-01 / I18N-KEY-02）
token-revoked = Token 已吊销: {$detail}
firewall-blocked = 防火墙拦截: {$detail}

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

# --- 华为 Account Kit（huawei，sinnan 自定义 provider）---
huawei-token-request-failed = 华为 token 请求失败: {$detail}
huawei-token-response-parse-failed = 华为 token 响应解析失败: {$detail}
huawei-error-response = 华为错误响应: {$detail}
huawei-token-response-missing-access-token = 华为 token 响应缺少 access_token 字段
huawei-get-user-info-failed-after-token-exchange = 华为 token 交换后获取用户信息失败（code 已消耗，请重新发起授权）: {$detail}
huawei-userinfo-request-failed = 华为用户信息请求失败: {$detail}
huawei-userinfo-response-parse-failed = 华为用户信息响应解析失败: {$detail}
huawei-userinfo-business-error = 华为用户信息业务错误: {$detail}
huawei-userinfo-response-missing-openID = 华为用户信息响应缺少 openID 字段

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
manager-not-init = GarrisonManager 未初始化
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
plugin-on-permission-check-failed = on_permission_check 校验失败
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
secure-email-code-wrong = 验证码错误
secure-email-empty = email 不能为空
secure-email-no-colon = email 不能包含冒号
secure-email-no-control-char = email 不能包含控制字符
secure-email-invalid-format = email 格式无效
secure-email-code-mail-subject = 验证码
secure-email-code-mail-body = 您的验证码是：{$code}，{$minutes} 分钟内有效。
    如非本人操作，请忽略此邮件。
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
keycloak-dao-not-injected = KeycloakProvider 未注入 DAO, 无法缓存 JWKS (调用 with_dao 注入 GarrisonDao)
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

# --- SessionLogic trait 默认实现 + GarrisonLogicDefault impl ---
stp-revoke-all-sessions-not-implemented = revoke_all_sessions 需 GarrisonLogicDefault 实现
stp-get-active-sessions-not-implemented = get_active_sessions 需 GarrisonLogicDefault 实现
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
# Authflow executor 错误（i18n 迁移）
# ============================================================================
authflow-user-locked = 用户已被锁定: {$arg0}
authflow-login-needs-builder = Login 步骤需要 CredentialBuilder，请使用 execute_with_builder
authflow-login-needs-user-id = Login 步骤需要 user_id
authflow-credential-not-found = 未找到 {$arg0} 类型的凭证
authflow-credential-verify-failed = 凭证校验失败
authflow-enter-verification-code = 请输入 {$arg0} 验证码
authflow-mfa-needs-builder = Mfa(Some) 步骤需要 CredentialBuilder，请使用 execute_with_builder
authflow-mfa-needs-user-id = Mfa 步骤需要 user_id
authflow-verify-failed = {$arg0} 校验失败
authflow-max-depth-exceeded = AuthenticationFlow 嵌套深度超过 {$arg0} 层上限，疑似循环引用
authflow-subflow-not-found = 未找到子流程: {$arg0}
authflow-subflow-failed = 子流程 {$arg0} 失败: {$arg1}
authflow-subflow-pending = 子流程 {$arg0} 返回 Pending，v0.6.0 不支持嵌套 Pending 传播
authflow-social-needs-resolver = SocialProvider 步骤需要 SocialProviderResolver，请使用 execute_with_full
authflow-complete-social-auth = 请完成 {$arg0} 社交登录授权
authflow-social-login-failed = 社交登录 {$arg0} 失败: {$arg1}
authflow-sso-needs-resolver = SsoServer 步骤需要 SsoServerResolver，请使用 execute_with_full
authflow-complete-sso-auth = 请完成 SSO 登录: {$arg0}
authflow-sso-verify-failed = SSO 票据校验失败: {$arg0}
authflow-step-enter = 请输入 {$arg0}
authflow-step-enter-code = 请输入 {$arg0} 验证码
authflow-step-complete-mfa = 请完成 MFA 校验
authflow-step-complete-social = 请完成 {$arg0} 社交登录
authflow-step-complete-sso = 请完成 SSO 登录: {$arg0}
authflow-step-complete-action = 请完成必需动作: {$arg0}
authflow-step-complete-condition = 请完成条件分支
authflow-step-complete-subflow = 请完成子流程: {$arg0}

# ============================================================================
# Config loader 错误（i18n 迁移）
# ============================================================================
config-path-empty = 配置文件路径不能为空
config-path-illegal-parent = 配置文件路径包含非法的父目录引用（..）：{$arg0}
config-open-failed = 打开配置文件失败 [{$arg0}]：{$arg1}
config-metadata-failed = 读取配置文件元数据失败 [{$arg0}]：{$arg1}
config-not-regular-file = 配置文件路径不是普通文件 [{$arg0}]：{$arg1}
config-too-large = 配置文件过大 [{$arg0}]：{$arg1} bytes，上限 {$arg2} bytes
config-read-failed = 读取配置文件失败 [{$arg0}]：{$arg1}

# ============================================================================
# Session 事件 reason / Stp 硬编码消息（i18n 迁移）
# ============================================================================
session-kickout-admin = 管理员强制下线
session-overflow-kickout = 超过最大登录数限制
session-overflow-replaced = 超过最大登录数限制，被新会话顶替
stp-verify-token-not-implemented = verify_token 需子类 override 委托 core-token::Token::verify
stp-refresh-token-not-implemented = refresh_token 需启用 protocol-jwt feature
stp-refresh-token-jwt-only = refresh_token 仅在 token_style=jwt 时可用
stp-mfa-not-passed = 二级认证未通过

# ============================================================================
# i18n 硬编码字符串修复（fix-i18n-hardcoded-strings）
# ============================================================================

# --- stp/util ---
stp-permission-empty = permission 不能为空
stp-role-empty = role 不能为空

# --- protocol/jwt ---
jwt-timeout-negative = timeout 不能为负数: {$arg0}

# --- secure ---
secure-verify-totp-not-implemented = verify_totp 未实现
secure-generate-totp-not-implemented = generate_totp 未实现
secure-verify-sign-not-implemented = verify_sign 未实现
secure-create-sign-not-implemented = create_sign 未实现
sanitize-input-length-exceeded = 输入长度 {$arg0} 超过最大限制 {$arg1}
digest-algo-unsupported = 不支持的 Digest 算法: {$arg0}，仅支持 MD5 / SHA256

# --- dao ---
dao-decr-parse-u64 = decr: 现存值非 u64，key={$arg0}, value={$arg1}
counter-overflow = 计数器溢出: key={$arg0}

# --- strategy ---
strategy-login-frequency-exceeded = 登录频率超限：IP {$arg0}
strategy-account-locked = 账号锁定：login_id={$arg0}
strategy-geo-anomaly = 异地登录检测：login_id={$arg0} 上次地理位置 {$arg1} 与本次不符
strategy-token-reuse-blocked = Token 复用检测：login_id={$arg0} 的 Token 已被列入黑名单
strategy-device-anomaly = 设备异常检测：login_id={$arg0} 的设备指纹 {$arg1} 不在已知设备列表

# --- abac ---
abac-expr-length-exceeded = abac_expr 长度超过 {$arg0} 字符（DoS 防御）
abac-expr-illegal-char = abac_expr 含策略终止符（疑似策略注入）
abac-expr-no-declaration = abac_expr 不允许声明 permit/forbid 策略
abac-expr-must-reference-context = abac_expr 必须引用 principal/resource/action 之一（拒绝纯字面量）
abac-engine-not-init = AbacEngine 未初始化，ABAC 校验失败（fail-closed）
abac-login-id-missing = ABAC 校验时未获取到 login_id
abac-policy-denied = ABAC 策略拒绝: action={$arg0}, resource={$arg1}

# --- credit ---
credit-alert-thresholds-empty = alert_thresholds 不能为空
credit-alert-thresholds-range = alert_thresholds[{$arg0}] = {$arg1} 超出范围 [0, 100]
credit-alert-thresholds-order = alert_thresholds 必须严格升序: {$arg0} <= {$arg1}

# --- web/cors ---
cors-credentials-wildcard = CORS 配置冲突：allow_credentials=true 时不允许 allowed_origins 包含通配符 "*"

# --- context/tenant ---
ctx-tenant-id-missing = X-Tenant-Id header 缺失

# ============================================================================
# response_parts 专用 message keys（不含 detail，用于 HTTP 响应体）
# ============================================================================
# 这些 key 用于 GarrisonError::response_parts_i18n() 方法，返回不含变体 detail
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
invalid-response-msg = 上游响应无效
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
email-rate-limit-exceeded-msg = 邮件发送频繁
email-verify-max-attempts-msg = 验证码尝试次数超限
email-code-not-found-msg = 验证码不存在或已过期
email-channel-recycled-msg = 邮件通道已回收
credit-insufficient-msg = Credit 不足
# Exception 变体依据 code 字段映射的 message
exception-not-login-msg = 未登录
exception-not-permission-msg = 无权限
exception-default-msg = 业务异常

# ============================================================================
# 密码策略规则消息（i18n 迁移）
# ============================================================================
policy-length-too-short = 密码长度 {$arg0} 小于最小要求 {$arg1}
policy-length-too-long = 密码长度 {$arg0} 超过最大限制 {$arg1}
policy-history-duplicate = 密码与历史密码重复
policy-blacklist-match = 密码在黑名单中
policy-contains-username = 密码包含用户名
policy-common-password = 密码为常见密码
policy-dictionary-word = 密码为字典单词
policy-contains-email-prefix = 密码包含邮箱前缀
policy-hibp-requires-feature = HIBP 检查需要启用 policy-hibp feature
policy-nist-length-too-short = 密码长度 {$arg0} 小于 NIST SP 800-63B 最小要求 {$arg1}
policy-max-age-expired = 密码已过期，请修改密码

# ============================================================================
# 会话劫持检测消息（i18n 迁移）
# ============================================================================
session-ip-mismatch = 会话 IP 不一致: 存储={$arg0}, 当前={$arg1}

# ============================================================================
# WAF 拦截原因消息（i18n 迁移）
# ============================================================================
waf-blacklist-path = 路径 {$arg0} 命中黑名单
waf-danger-char-path = 路径包含危险字符 {$arg0}
waf-danger-char-param = 参数值包含危险字符 {$arg0}
waf-danger-char-header = 请求头值包含危险字符 {$arg0}
waf-banned-char = 路径包含不可打印字符 {$arg0}
waf-dir-traversal = 路径包含目录遍历模式 {$arg0}
waf-host-not-allowed = Host {$arg0} 不在白名单中
waf-method-not-allowed = HTTP 方法 {$arg0} 不在允许列表中
waf-header-banned = 请求头 {$arg0} 在禁止列表中
waf-param-banned = 参数 {$arg0} 在禁止列表中

# --- WAF 危险字符描述 ---
waf-danger-desc-double-slash = 双斜杠 //
waf-danger-desc-backslash = 反斜杠 \\
waf-danger-desc-semicolon = 分号 ;
waf-danger-desc-null-byte = 空字节
waf-danger-desc-newline = 换行符
waf-danger-desc-carriage-return = 回车符
waf-danger-desc-pct-2e = 百分号编码 %2e
waf-danger-desc-pct-2f = 百分号编码 %2f
waf-danger-desc-pct-00 = 百分号编码 %00
waf-danger-desc-pct-5c = 百分号编码 %5c
waf-danger-desc-pct-3b = 百分号编码 %3b
waf-danger-desc-pct-0a = 百分号编码 %0a
waf-danger-desc-pct-0d = 百分号编码 %0d

# ============================================================================
# 同形异义字检测消息（i18n 迁移）
# ============================================================================
confusable-suggestion = 考虑用 '{$arg0}' 替换 '{$arg1}'

# ============================================================================
# OAuth2 PKCE / state / refresh 消息（i18n 迁移）
# ============================================================================
oauth2-pkce-length-invalid = code_verifier 长度必须在 43-128 之间，当前 {$arg0}
oauth2-pkce-chars-invalid = code_verifier 仅允许 [A-Z]/[a-z]/[0-9]/-/./_/~ 字符
oauth2-state-mismatch = state 参数不匹配，可能遭受 CSRF 攻击
oauth2-refresh-token-empty = refresh_token 不可为空

# ============================================================================
# 安全告警检测消息（i18n 迁移）
# ============================================================================
alert-ip-changed = IP 从 {$arg0} 变为 {$arg1}
alert-rapid-successive = {$arg0} 个 token 同时在线（阈值 {$arg1}）

# ============================================================================
# ABAC principal 校验消息（i18n 迁移）
# ============================================================================
abac-principal-control-char = login_id 包含控制字符

# ============================================================================
# Core 认证 / 权限消息（i18n 迁移）
# ============================================================================
core-switch-to-denied = switch_to 被拒绝：未配置 SwitchToGuard，默认 deny-all
core-switch-to-not-implemented = switch_to 未实现: {$arg0} 不支持身份切换
core-renew-not-implemented = renew_to_equivalent 未实现: {$arg0} 不支持 token 置换
core-account-no-permission = 账号 {$arg0} 未持有权限: {$arg1}
core-account-no-role = 账号 {$arg0} 未持有角色: {$arg1}
core-permission-name-empty = permission name 不能为空
core-permission-already-registered = permission 已注册: {$arg0}
core-permission-not-registered = 权限未在注册表中注册: {$arg0}

# ============================================================================
# Core token 风格消息（i18n 迁移）
# ============================================================================
core-token-parse-not-supported = {$arg0} token 风格不支持 parse（无 payload）
core-simple-secret-too-short = SimpleTokenStyle secret 长度必须 >= 32 字节（对齐 JWT 强校验）
core-simple-token-uuid-invalid = Simple token 格式错误：UUID 部分无效
core-simple-token-hmac-failed = Simple token HMAC 校验失败
core-simple-requires-feature = SimpleTokenStyle 需启用 secure-simple-token feature（A11 安全修复）

# ============================================================================
# DAO 未实现消息（i18n 迁移）
# ============================================================================
dao-not-implemented = {$arg0} 未实现：当前后端不支持

# ============================================================================
# 配置校验消息（i18n 迁移）
# ============================================================================
config-jwt-secret-empty = jwt_secret 不能为空（当 token_style=jwt 时）
config-jwt-algorithm-unsupported = 不支持的 jwt_algorithm: {$arg0}（仅支持 HS256/HS384/HS512）
config-jwt-secret-too-short = jwt_secret 长度不足：{$arg0}，实际 {$arg1} 字节
config-anon-timeout-invalid = anon_session_timeout 必须 > 0
config-l1-ttl-invalid = l1_cache_ttl_secs 必须 > 0
config-l2-ttl-invalid = l2_cache_ttl_secs 必须 > 0
config-l1-capacity-invalid = l1_cache_capacity 必须 > 0
config-redis-url-empty = rate_limit_backend=Redis 时 redis_url 不能为空
config-waf-method-case = waf_allowed_methods 中的方法必须为大写，实际: {$arg0}
config-sms-hourly-invalid = sms_hourly_limit 必须大于 0
config-sms-daily-invalid = sms_daily_limit 必须 >= sms_hourly_limit
config-sms-max-attempts-invalid = sms_verify_max_attempts 必须大于 0
config-sms-threshold-invalid = sms_unverified_threshold 必须大于 0
config-email-hourly-invalid = email_hourly_limit 必须大于 0
config-email-daily-invalid = email_daily_limit 必须 >= email_hourly_limit
config-email-max-attempts-invalid = email_verify_max_attempts 必须大于 0
config-email-threshold-invalid = email_unverified_threshold 必须大于 0
config-email-ttl-invalid = email_code_ttl 必须大于 0
config-anomalous-interval-invalid = anomalous_analyzer_interval_secs 必须 >= 60
config-anomalous-burst-invalid = anomalous_analyzer_burst_threshold 必须大于 0

# ============================================================================
# 会话搜索消息（i18n 迁移）
# ============================================================================
session-search-keyword-too-long = keyword 长度超限：{$arg0} > {$arg1}
session-search-size-exceeded = size 超限：{$arg0} > {$arg1}

# ============================================================================
# STP 模块消息（i18n 迁移）
# ============================================================================
stp-service-empty = service 参数不能为空
stp-not-implemented = {$arg0} 未实现

# ============================================================================
# 策略防火墙消息（i18n 迁移）
# ============================================================================
firewall-anomalous-requires-login-id = AnomalousLogin 需要 login_id 但 ctx.login_id 为 None
firewall-anomalous-geo-parse-failed = 历史 geo 坐标解析失败（key={$arg0}, value={$arg1}）
firewall-anomalous-distance-exceeded = anomalous: 用户 {$arg0} 从 {$arg1} 登录，{$arg2}
firewall-geo-lat-out-of-range = GeoCoord: lat {$arg0} 越界 [-90, 90]
firewall-geo-lon-out-of-range = GeoCoord: lon {$arg0} 越界 [-180, 180]
firewall-geoip-not-in-whitelist = geoip: IP {$arg0} 国家码 {$arg1} 不在白名单
firewall-geoip-no-country = geoip: IP {$arg0} 无法定位国家，不在白名单内
firewall-geoip-in-blacklist = geoip: IP {$arg0} 国家码 {$arg1} 在黑名单内
firewall-maxmind-city-decode-failed = MaxMindDb 解码 City 记录失败 (IP={$arg0}): {$arg1}
firewall-maxmind-country-decode-failed = MaxMindDb 解码 Country 记录失败 (IP={$arg0}): {$arg1}
firewall-rate-limit-no-login-id = RateLimit scope=User 但 ctx.login_id 为 None
firewall-rate-limit-no-tenant-id = RateLimit scope=Tenant 但 ctx.tenant_id 为 None
firewall-user-locked-permanent = user-lockout: 用户 {$arg0} 已被永久锁定
firewall-user-locked-temporary = user-lockout: 用户 {$arg0} 已被临时锁定，直到 {$arg1}

# ============================================================================
# Account 模块消息（i18n 迁移）
# ============================================================================
account-totp-parse-failed = TOTP secret_data 解析失败（期望 JSON 包含 secret/step/digits 字段）: {$arg0}
account-disable-service-colon = service 不能包含冒号（避免 key 注入）: {$arg0}
account-disable-login-id-colon = login_id 不能包含冒号（避免 key 注入）: {$arg0}

# ============================================================================
# Protocol 模块消息（i18n 迁移）
# ============================================================================
oidc-algorithm-unsupported = OidcHandler 仅支持 HS256/HS384/HS512 算法，当前算法不支持: {$arg0}
oidc-iss-mismatch = OIDC iss 不匹配: token 中的 issuer 与期望不符
oidc-aud-mismatch = OIDC aud 不匹配: token 中的 audience 不包含本客户端 client_id
temp-prefix-colon = prefix 不可包含 ':'
temp-ttl-invalid = ttl_seconds 必须大于 0
sso-secret-empty = SSO secret 不能为空（依据安全审计 M5：ticket 必须签名）

# ============================================================================
# Server / HTTP 层消息（i18n 迁移）
# ============================================================================
server-rate-limited = 请求过于频繁
server-invalid-api-key = 无效的 API Key
server-prometheus-encode-failed = Prometheus 指标编码失败
server-internal-api-key-missing = internal_api_key 未配置，内网 API 将拒绝所有请求。请通过 with_internal_api_key() 设置非空值

# ============================================================================
# 剩余防火墙 / 账号 / OIDC / OTel 消息（i18n 迁移）
# ============================================================================
firewall-anomalous-need-login-id = AnomalousLogin 需要 login_id 但 ctx.login_id 为 None
firewall-ratelimit-user-none = RateLimit scope=User 但 ctx.login_id 为 None
firewall-ratelimit-tenant-none = RateLimit scope=Tenant 但 ctx.tenant_id 为 None
user-lockout-permanent = 用户 {$arg0} 已被永久锁定
user-lockout-temporary = 用户 {$arg0} 已被临时锁定，直到 {$arg1}
oidc-timeout-negative = timeout 不能为负数: {$arg0}
otel-exporter-failed = OTLP exporter 构造失败: {$arg0}
otel-provider-failed = Tracer provider 设置失败: {$arg0}

# ============================================================================
# 报告遗漏（config-load / dao-repo / cache / authflow / annotation）
# ============================================================================
config-file-size-exceeded = 配置文件实际大小超过上限 [{$arg0}]：{$arg1} bytes
config-rate-limit-backend-unsupported = GARRISON_RATE_LIMIT_BACKEND 不支持的值 '{$arg0}'，仅支持 'memory' 或 'redis'
dao-user-device-limit-exceeded = 用户（{$arg0}）设备数已达上限，最多 {$arg1}
cache-l1-ttl-must-positive = UserCacheService::new: l1_ttl_secs 必须 > 0
cache-l2-ttl-must-positive = UserCacheService::new: l2_ttl_secs 必须 > 0
authflow-required-action-not-implemented = RequiredAction 步骤在 v0.6.0 未实现
annotation-parse-failed = 无法从字符串解析注解（含数据变体需显式构造）: {$arg0}
stp-stateless-jwt-requires-revocation = token_style=jwt 且 jwt_mode=Stateless 时必须启用 enable_jwt_revocation（三选一：1) 开启 JWT 撤销黑名单 enable_jwt_revocation=true；2) 改用 JwtMode::Mixin；3) 显式风险接受开关 allow_stateless_jwt_no_revocation=true）
config-unknown-token-style-jwt = 不支持的 token_style: jwt（需启用 protocol-jwt feature）

# ============================================================================
# i18n 审计 2026-09：key:: 约定缺失的 FTL 消息补齐（P2）
# ============================================================================

# --- apikey ---
apikey-namespace-reserved = API Key 命名空间 '{$arg0}' 为保留名称
apikey-scope-not-allowed = API Key scope '{$arg0}' 不在允许范围内

# --- authflow ---
authflow-unknown-custom-condition = 未知自定义条件: {$arg0}
ip-whitelist-parse-failed = IP 白名单条目 '{$arg0}' 解析失败: {$arg1}

# --- limiteron 熔断器 ---
circuit-open = 熔断器已打开: {$arg0}
circuit-limited = 熔断器限流拒绝请求: {$arg0}
circuit-breaker = 熔断器错误: {$arg0}

# --- core token ---
core-simple-token-no-sep = Simple token 格式错误：缺少单元分隔符

# --- credit 计量 ---
credit-config-invalid = 计量配置无效: {$arg0}
credit-dao = 计量 DAO 错误: {$arg0}
credit-get-consumed = 读取计量已用额度失败: {$arg0}
credit-incr-failed = 计量额度递增失败: {$arg0}
credit-query-history = 查询计量历史失败: {$arg0}
credit-set-meta-failed = 写入计量元数据失败: {$arg0}
credit-get-meta = 读取计量元数据失败: {$arg0}
credit-reset-consumed = 重置计量已用额度失败: {$arg0}
credit-reset-meta = 重置计量元数据失败: {$arg0}
credit-reset-window-start = 重置计量窗口起点失败: {$arg0}
credit-get-window-start = 读取计量窗口起点失败: {$arg0}
credit-set-window-start = 写入计量窗口起点失败: {$arg0}
credit-consumed-parse-failed = 计量已用额度解析失败: {$arg0}, {$arg1}
credit-meta-format-error = 计量元数据格式错误: {$arg0}, {$arg1}
credit-meta-consumed-parse-failed = 计量元数据已用额度解析失败: {$arg0}, {$arg1}
credit-meta-limit-parse-failed = 计量元数据上限解析失败: {$arg0}, {$arg1}
credit-meta-window-start-parse-failed = 计量元数据窗口起点解析失败: {$arg0}, {$arg1}
credit-meta-window-end-parse-failed = 计量元数据窗口终点解析失败: {$arg0}, {$arg1}
credit-meta-cycle-param-parse-failed = 计量元数据周期参数解析失败: {$arg0}, {$arg1}
credit-meta-unknown-cycle-type = 计量元数据未知周期类型: {$arg0}, {$arg1}
credit-window-start-parse-failed = 计量窗口起点解析失败: {$arg0}, {$arg1}

# --- dao ---
dao-role-hierarchy-add-edge-connection = 角色层级添加边 connection 失败: {$arg0}
dao-role-hierarchy-delete-edge-session = 角色层级删除边 session 失败: {$arg0}
dao-role-hierarchy-delete-edge-connection = 角色层级删除边 connection 失败: {$arg0}
dao-role-hierarchy-delete-edge = 角色层级删除边失败: {$arg0}
dao-social-binding-session = 社交绑定 session 失败: {$arg0}
dao-social-binding-conn = 社交绑定 connection 失败: {$arg0}
dao-social-binding-insert-session = 社交绑定写入 session 失败: {$arg0}
dao-social-binding-insert-conn = 社交绑定写入 connection 失败: {$arg0}
dao-social-binding-insert = 社交绑定写入失败: {$arg0}
embedded-migrations-tempdir = 为内嵌迁移创建临时目录失败: {$arg0}
embedded-migrations-write = 写入内嵌迁移文件失败: {$arg0}
embedded-migrations-readdir = 读取内嵌迁移目录失败: {$arg0}
embedded-migrations-direntry = 读取内嵌迁移目录项失败: {$arg0}
dao-app-role-permission-find-by-role-id-query = 按角色 ID 查询角色权限失败: {$arg0}
dao-app-role-permission-find-by-permission-id-query = 按权限 ID 查询角色权限失败: {$arg0}
dao-app-role-permission-row-parse-permission-id = 解析权限 ID 失败: {$arg0}
dao-app-user-device-row-parse-device-identifier = 解析设备标识失败: {$arg0}
dao-eval-lua-unsupported-script = 当前后端不支持该 eval_lua 脚本: {$arg0}
dao-oxcache-cas-get-sync = oxcache CAS 读取（同步）失败: {$arg0}
dao-oxcache-cas-set-sync = oxcache CAS 写入（同步）失败: {$arg0}
dao-oxcache-eval-lua = oxcache eval_lua 失败: {$arg0}
dao-oxcache-sync-api-incompatible-with-redis = _sync API（set_if_absent/incr/decr/get_and_delete）与 Redis L2 后端不兼容，请改用 async API 或移除 with_redis_config 调用

# --- 密码策略 / HIBP ---
hibp-client-build-failed = HIBP 客户端构建失败: {$arg0}
hibp-http-status = HIBP 请求返回异常状态: {$arg0}, {$arg1}
hibp-request-failed = HIBP 请求失败: {$arg0}, {$arg1}
hibp-body-read-failed = HIBP 响应体读取失败: {$arg0}

# --- jwt ---
jwt-secret-too-short = jwt secret 长度不足: {$arg0}, {$arg1}
jwt-refresh-login-id-parse-failed = jwt refresh login_id 解析失败: {$arg0}, {$arg1}
jwt-refresh-cleanup-get-session = jwt refresh 清理：读取 session 失败: {$arg0}
jwt-refresh-cleanup-get-conn = jwt refresh 清理：获取连接失败: {$arg0}
jwt-refresh-cleanup-delete = jwt refresh 清理：删除失败: {$arg0}
jwt-revoked = JWT 已被吊销: {$arg0}

# --- limiteron ---
limiteron-ban-history-format-error = limiteron 封禁历史格式错误: {$arg0}, {$arg1}
limiteron-ban-history-parse-ban-times = limiteron 封禁历史 ban_times 解析失败: {$arg0}, {$arg1}
limiteron-ban-history-parse-last-banned = limiteron 封禁历史 last_banned 解析失败: {$arg0}, {$arg1}
limiteron-ban-times-parse-failed = limiteron 封禁次数解析失败: {$arg0}, {$arg1}
limiteron-eval-lua-parse-failed = limiteron eval_lua 结果解析失败: {$arg0}
limiteron-get-count-parse-failed = limiteron 计数读取解析失败: {$arg0}, {$arg1}
limiteron-quota-count-parse-failed = limiteron 配额计数解析失败: {$arg0}, {$arg1}
limiteron-quota-meta-format-error = limiteron 配额元数据格式错误: {$arg0}, {$arg1}
limiteron-quota-limit-parse-failed = limiteron 配额上限解析失败: {$arg0}, {$arg1}
limiteron-quota-window-start-parse-failed = limiteron 配额窗口起点解析失败: {$arg0}, {$arg1}
limiteron-quota-window-end-parse-failed = limiteron 配额窗口终点解析失败: {$arg0}, {$arg1}
limiteron-quota-window-start-datetime-failed = limiteron 配额窗口起点时间构造失败: {$arg0}
limiteron-quota-window-end-datetime-failed = limiteron 配额窗口终点时间构造失败: {$arg0}

# --- manager ---
manager-active-timeout-overflow = active_timeout 溢出 u64: {$arg0}

# --- secure ---
secure-httpbasic-unsupported-scheme = HTTP Basic: 不支持的认证方案: {$arg0}
secure-httpdigest-unsupported-scheme = HTTP Digest: 不支持的认证方案: {$arg0}
secure-http-digest-missing-uri = HTTP Digest: 缺少 uri 参数

# --- sso / saml ---
sso-oidc-body-exceeds-limit = SSO OIDC 响应体超过大小限制: {$arg0}
saml-response-too-large = SAML 响应过大: {$arg0}, {$arg1}
sso-saml-assertion-replay = 检测到 SAML Assertion 重放: {$arg0}
sso-saml-status-not-success = SAML 响应状态非 Success: {$arg0}
sso-saml-destination-mismatch = SAML Destination 不匹配: {$arg0}, {$arg1}
sso-saml-audience-mismatch = SAML Audience 不匹配: {$arg0}, {$arg1}
sso-saml-not-before-parse = SAML NotBefore 解析失败: {$arg0}
sso-saml-assertion-not-yet-valid = SAML Assertion 尚未生效: {$arg0}
sso-saml-in-response-to-unknown = SAML InResponseTo 未知或已过期: {$arg0}
sso-saml-signature-value-decode = SAML 签名值解码失败: {$arg0}
sso-saml-signature-bytes-decode = SAML 签名字节解码失败: {$arg0}
sso-saml-idp-public-key-parse-failed = SAML IdP 公钥解析失败: {$arg0}, {$arg1}

# --- stp ---
stp-login-ip-blocked = 登录被拒绝：IP {$arg0} 已被封禁
stp-check-login-ip-blocked = 校验登录被拒绝：IP {$arg0} 已被封禁
stp-apikey-ip-blocked = API Key 请求被拒绝：IP {$arg0} 已被封禁
stp-simple-token-style-requires-secure-simple-token-feature = token_style=simple 需启用 secure-simple-token feature

# --- strategy / firewall ---
strategy-firewall-bruteforce-reason = 爆破封禁原因：尝试 {$arg0} 次超过上限 {$arg1}
strategy-firewall-bruteforce-locked = IP {$arg0} 因爆破已被封禁
strategy-firewall-bruteforce-blocked = 爆破拦截：IP {$arg0}, {$arg1}
strategy-firewall-ratelimit-blocked = 限流拦截：scope {$arg0}, {$arg1}
strategy-limiter-eval-lua = 限流器 eval_lua 失败: {$arg0}
strategy-ddos-global-blocked = DDoS 全局限流已超限（{$arg0} req/s）
strategy-ddos-ip-blocked = DDoS 单 IP 限流已超限：{$arg0}（{$arg1} req/s）
strategy-analyzer-shutdown-timeout = 异常分析器关闭超时: {$arg0}

# ============================================================================
# i18n 审计 2026-09：loc! 引用了不存在的 FTL 消息（P3）
# ============================================================================
alipay-response-missing-oauth-token-response = alipay 响应缺少 alipay_system_oauth_token_response 字段
alipay-response-missing-access-token = alipay 响应缺少 access_token 字段
session-kickout-password-changed = 密码已变更

# ============================================================================
# i18n 审计 2026-09：英文裸错误消息迁移到 key:: 约定（P1）
# ============================================================================
abac-engine-already-initialized = AbacEngine 已初始化
backend-unknown-error = 未知错误
config-confers-build-failed = confers 构建失败: {$arg0}
config-unknown-token-style = 不支持的 token_style: {$arg0}
config-unknown-cookie-same-site = 不支持的 cookie_same_site: {$arg0}（应为 Lax/Strict/None）
config-unknown-device-binding-mode = 不支持的 device_binding_mode: {$arg0}（应为 strict/loose/disabled）
config-timeout-must-positive = timeout 必须为正数
config-remember-me-timeout-mismatch = remember_me_timeout（{$arg0}）必须大于 timeout（{$arg1}）
config-remember-me-timeout-positive = remember_me_timeout 必须为正数，当前值: {$arg0}
credential-already-exists = 凭证已存在: {$arg0}
credential-not-found = 凭证不存在: {$arg0}
credential-backup-code-not-found = DAO 中未找到备份码凭证: {$arg0}
credential-query-forbidden = 调用方 {$arg0} 无权查询 {$arg1} 的凭证
credential-update-forbidden = 调用方 {$arg0} 无权更新凭证 {$arg1}
credential-delete-forbidden = 调用方 {$arg0} 无权删除凭证 {$arg1}
credential-transfer-forbidden = 无权转移凭证 {$arg0}: {$arg1}
credential-totp-step-invalid = TOTP 步长必须大于 0
ctx-invalid-header-name = 非法 header 名称 '{$arg0}': {$arg1}
ctx-invalid-header-value = 非法 header 值 '{$arg0}': {$arg1}
ctx-invalid-status-code = 非法状态码 {$arg0}: {$arg1}
ctx-tenant-id-not-ascii = X-Tenant-Id 含不可见 ASCII 字符: {$arg0}
ctx-host-missing = Host header 缺失
ctx-host-not-ascii = Host 含不可见 ASCII 字符: {$arg0}
ctx-host-empty-subdomain = 非法 Host '{$arg0}'：子域为空
ctx-host-unknown-subdomain = 未知子域 '{$arg0}'
ctx-auth-header-missing = Authorization header 缺失
ctx-auth-not-ascii = Authorization 含不可见 ASCII 字符: {$arg0}
ctx-auth-token-missing = Authorization header 中缺少 token
ctx-auth-scheme-unsupported = 不支持的认证方案 '{$arg0}'（应为 Bearer）
permission-name-too-long = permission 过长: {$arg0} 字节（上限 256）
oauth2-server-client-id-invalid = 无效的 client_id: {$arg0}
jwt-refresh-token-consumed = refresh token 不存在或已被消费
oauth2-scope-handler-not-registered = scope handler 未注册: {$arg0}
url-scheme-https-required = {$arg0} 必须为 https 或 localhost，当前为: {$arg1}
sso-saml-signature-mismatch = SAML 验签失败：签名值与 SignedInfo 不匹配
stp-apikey-feature-required = check_api_key 需要 protocol-apikey feature（fail-closed：启用该 feature 或移除相关检查）
stp-mock-not-implemented = MockUserRepository::create 未实现
stp-param-login-id-missing = ParameterQuery 上下文中未设置 login_id
stp-password-hasher-not-configured = 未配置密码哈希器
stp-user-repo-not-configured = 未配置用户仓库
stp-invalid-password = 密码错误
stp-token-login-id-bound = token 已绑定 login_id: {$arg0}
stp-backend-already-init = Backend 已初始化
stp-backend-not-init = Backend 未初始化，请先调用 init_backend()
testing-json-parse-error = JSON 解析错误: {$arg0}

# --- P1 迁移过程中发现的额外英文裸消息 ---
stp-unsupported-hash-format = 不支持的哈希格式
ctx-auth-header-empty = Authorization header 为空
ctx-tenant-jwt-verify-failed = JWT 验证失败: {$arg0}
abac-engine-lock-poisoned = AbacEngine 锁已中毒
config-auto-renewal-threshold-invalid = auto_renewal_threshold 必须为 -1 或 0-100，当前值: {$arg0}
config-is-share-requires-concurrent = is_share=true 要求 is_concurrent=true
config-session-hover-timeout-exceeds = session_hover_timeout（{$arg0}）超过允许上限 {$arg1} 秒（10 年）
stp-backend-lock-poisoned = Backend 锁已中毒
session-ip-subnet-changed = 检测到 IP 网段变更：token={$arg0}，{$arg1}
invitation-code-invalid = 邀请码格式无效：{$arg0}
invitation-code-collision = 邀请码碰撞，请重试
invitation-code-not-found = 邀请码不存在
invitation-code-expired = 邀请码已过期
invitation-code-revoked = 邀请码 {$arg0} 已被吊销
invitation-code-exhausted = 邀请码 {$arg0} 已达使用上限
invitation-too-many-attempts = 来自 {$arg0} 的兑换尝试次数过多
invitation-ttl-invalid = 邀请码 TTL 值无效
invitation-max-uses-invalid = 邀请码 max_uses 值无效
invitation-count-invalid = 邀请码批量数量无效
invitation-serialize-failed = 邀请码序列化失败：{$arg0}
