# Garrison 异常消息中文翻译
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

# 网关层限流（GarrisonError::RateLimited，R04 统一错误模型）
rate-limited = 请求过于频繁

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

# 社交登录异常消息（0.6.0 新增）

# 微信扫码登录（wechat）
wechat-token-request-failed = 微信 token 请求失败: {$detail}
wechat-token-response-parse-failed = 微信 token 响应解析失败: {$detail}
wechat-error-response = 微信错误 {$code}: {$message}
wechat-response-missing-openid = 微信响应缺少 openid 字段
wechat-userinfo-request-failed = 微信用户信息请求失败: {$detail}
wechat-userinfo-response-parse-failed = 微信用户信息响应解析失败: {$detail}
wechat-userinfo-response-missing-openid = 微信用户信息响应缺少 openid 字段
wechat-redirect-uri-must-be-https = 微信 redirect_uri 必须为 https URL

# 第一方扫码登录（qrlogin）
qrlogin-secret-empty = 扫码登录 HMAC 密钥不能为空
qrlogin-secret-too-short = 扫码登录 HMAC 密钥不能为空
qrlogin-session-not-found = 扫码登录会话不存在
qrlogin-session-expired = 扫码登录会话已过期
qrlogin-invalid-ticket = 扫码登录票据签名无效
qrlogin-already-scanned = 扫码登录会话已被扫码
qrlogin-not-scanned = 扫码登录会话尚未被扫码
qrlogin-already-consumed = 扫码登录会话已被消费
qrlogin-cancelled = 扫码登录会话已取消
qrlogin-confirm-token-invalid = 扫码登录确认凭据无效或已过期
qrlogin-domain-not-allowed = 扫码登录票据域名不在白名单内
qrlogin-issuer-failed = 扫码登录会话签发失败: {$detail}
qrlogin-app-unauthorized = 扫码登录需要有效的应用会话 token
qrlogin-action-invalid = action 必须为 "confirm" 或 "cancel"

# 微信小程序（wechat mini-app）
wechat-mini-app-get-authorization-url-not-supported = WechatMiniAppProvider 不支持 get_authorization_url（小程序用 wx.login() 直接获取 js_code）
wechat-mini-app-jscode2session-request-failed = 微信小程序 jscode2session 请求失败: {$detail}
wechat-mini-app-jscode2session-response-parse-failed = 微信小程序 jscode2session 响应解析失败: {$detail}
wechat-mini-app-error-response = 微信小程序错误 {$code}: {$message}
wechat-mini-app-jscode2session-response-missing-openid = 微信小程序 jscode2session 响应缺少 openid 字段

# 支付宝授权登录（alipay）
alipay-rsa-key-parse-failed = 支付宝 RSA 私钥解析失败: {$detail}
alipay-token-request-failed = 支付宝 token 请求失败: {$detail}
alipay-token-response-parse-failed = 支付宝 token 响应解析失败: {$detail}
alipay-error-response = 支付宝错误 {$code}: {$message}
alipay-response-missing-user-id = 支付宝响应缺少 user_id 字段
alipay-user-info-request-failed = 支付宝用户信息请求失败: {$detail}
alipay-user-info-response-parse-failed = 支付宝用户信息响应解析失败: {$detail}
alipay-response-missing-user-info-share-response = 支付宝响应缺少 alipay_user_info_share_response 字段
alipay-http-client-build-failed = 支付宝 HTTP 客户端构建失败: {$detail}

# Keycloak OIDC RP（keycloak）
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

# 华为 Account Kit（huawei，sinnan 自定义 provider）
huawei-token-request-failed = 华为 token 请求失败: {$detail}
huawei-token-response-parse-failed = 华为 token 响应解析失败: {$detail}
huawei-error-response = 华为错误响应: {$detail}
huawei-token-response-missing-access-token = 华为 token 响应缺少 access_token 字段
huawei-get-user-info-failed-after-token-exchange = 华为 token 交换后获取用户信息失败（code 已消耗，请重新发起授权）: {$detail}
huawei-userinfo-request-failed = 华为用户信息请求失败: {$detail}
huawei-userinfo-response-parse-failed = 华为用户信息响应解析失败: {$detail}
huawei-userinfo-business-error = 华为用户信息业务错误: {$detail}
huawei-userinfo-response-missing-openID = 华为用户信息响应缺少 openID 字段

# DAO 错误（i18n 改造）
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

# i18n 迁移补全（2026-07-18）

# session mock
session-mock-delete-failed = mock delete 失败: {$arg0}
session-mock-read-failed = mock read 失败: {$arg0}
session-mock-update-failed = mock update 失败: {$arg0}

# sso 补全
sso-mock-key-not-found = key 不存在
sso-oidc-token-status-error = token exchange 响应状态错误: {$arg0}
sso-oidc-userinfo-status-error = userinfo 响应状态错误: {$arg0}
sso-oidc-validate-not-implemented = OIDC id_token 验证未实现
sso-ticket-client-id-mismatch = SSO ticket client_id 不匹配: 期望 {$arg0}, 实际 {$arg1}
sso-ticket-consumed-by-concurrent = SSO ticket 被并发消费
sso-saml-signature-not-implemented = SAML 签名验证未实现
sso-saml-assertion-expired = SAML assertion 已过期: {$arg0}

# sign / apikey 补全
sign-app-secret-too-short = app_secret 长度不足: 当前 {$arg0} 字节, 要求至少 {$arg1} 字节 (256 位)
apikey-namespace-too-long = namespace 长度不能超过 64 字符, 实际: {$arg0}
apikey-namespace-invalid-chars = namespace 仅允许 [a-zA-Z0-9_-], 实际: {$arg0}
apikey-namespace-mismatch = API Key namespace 不匹配: 期望 {$arg0}, 实际 {$arg1}
apikey-expired-cannot-rotate = API Key 已过期, 无法轮换

# keycloak 补全
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

# server / backend 补全
server-caller-not-owner-kickout = caller 非属主且无 admin:sessions 权限, 禁止 kickout
server-caller-not-owner-switch-to = caller 非属主且无 admin:sessions 权限, 禁止 switch_to
backend-auth-logic-not-injected-renew = auth_logic 未注入, renew_to_equivalent 不可用

# oauth2_server 补全
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

# account 补全
account-password-unsupported-hash-format = 不支持的哈希格式: {$arg0}
account-backup-deserialize = backup_code secret_data 反序列化失败: {$arg0}

# Stp 层错误（i18n 改造 - session.rs 硬编码中文迁移）

# SessionLogic trait 默认实现 + GarrisonLogicDefault impl
stp-revoke-all-sessions-not-implemented = revoke_all_sessions 需 GarrisonLogicDefault 实现
stp-get-active-sessions-not-implemented = get_active_sessions 需 GarrisonLogicDefault 实现
stp-login-by-token-feature-required = login_by_token 需启用 protocol-oauth2 或 protocol-sso feature
stp-refresh-access-token-not-implemented-db = refresh_access_token 未实现：需启用 db-sqlite feature 并注入 RefreshTokenRotation
stp-refresh-access-token-no-rotation = refresh_access_token 未注入 RefreshTokenRotation
stp-refresh-access-token-feature-required = refresh_access_token 需启用 protocol-jwt + db-sqlite feature

# validate_login_with_token_inputs 输入校验
stp-token-length-too-short = token 长度不足: {$arg0} < 8
stp-token-length-too-long = token 长度超限: {$arg0} > 256

# login_inner NewDevice 模式
stp-new-device-login-rejected-not-allowed = 新设备登录被拒绝：当前为 NewDevice 模式，不允许新设备登录

# check_login_stateless / token_style feature 校验
stp-jwt-token-style-requires-protocol-jwt = jwt token_style 需启用 protocol-jwt feature
stp-stateless-requires-jwt-token-style = Stateless 模式要求 token_style=jwt
stp-stateless-requires-protocol-jwt = Stateless 模式要求启用 protocol-jwt feature
stp-unknown-token-style = 不支持的 token_style: {$arg0}

# auto_renewal 续签配置校验
stp-auto-renewal-no-auth-logic = auto_renewal_threshold 启用但 auth_logic 未注入，无法续签
stp-auto-renewal-jwt-requires-protocol-jwt = auto_renewal_threshold 启用且 token_style=jwt，但未启用 protocol-jwt feature

# MockAnomalyDetector 失败模拟
stp-mock-login-detection-failed = mock login detection 失败
stp-mock-check-login-detection-failed = mock check_login detection 失败

# Authflow executor 错误（i18n 迁移）
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

# Config loader 错误（i18n 迁移）
config-path-empty = 配置文件路径不能为空
config-open-failed = 打开配置文件失败 [{$arg0}]：{$arg1}
config-too-large = 配置文件过大 [{$arg0}]：{$arg1} bytes，上限 {$arg2} bytes

# Session 事件 reason / Stp 硬编码消息（i18n 迁移）
session-kickout-admin = 管理员强制下线
session-overflow-kickout = 超过最大登录数限制
session-overflow-replaced = 超过最大登录数限制，被新会话顶替
stp-verify-token-not-implemented = verify_token 需子类 override 委托 core-token::Token::verify
stp-refresh-token-not-implemented = refresh_token 需启用 protocol-jwt feature
stp-refresh-token-jwt-only = refresh_token 仅在 token_style=jwt 时可用
stp-mfa-not-passed = 二级认证未通过

# i18n 硬编码字符串修复（fix-i18n-hardcoded-strings）

# stp/util
stp-permission-empty = permission 不能为空
stp-role-empty = role 不能为空

# protocol/jwt
jwt-timeout-negative = timeout 不能为负数: {$arg0}

# secure
secure-verify-totp-not-implemented = verify_totp 未实现
secure-generate-totp-not-implemented = generate_totp 未实现
secure-verify-sign-not-implemented = verify_sign 未实现
secure-create-sign-not-implemented = create_sign 未实现
sanitize-input-length-exceeded = 输入长度 {$arg0} 超过最大限制 {$arg1}
digest-algo-unsupported = 不支持的 Digest 算法: {$arg0}，仅支持 MD5 / SHA256

# dao
dao-decr-parse-u64 = decr: 现存值非 u64，key={$arg0}, value={$arg1}
counter-overflow = 计数器溢出: key={$arg0}

# strategy
strategy-login-frequency-exceeded = 登录频率超限：IP {$arg0}
strategy-account-locked = 账号锁定：login_id={$arg0}
strategy-geo-anomaly = 异地登录检测：login_id={$arg0} 上次地理位置 {$arg1} 与本次不符
strategy-token-reuse-blocked = Token 复用检测：login_id={$arg0} 的 Token 已被列入黑名单
strategy-device-anomaly = 设备异常检测：login_id={$arg0} 的设备指纹 {$arg1} 不在已知设备列表

# abac
abac-expr-length-exceeded = abac_expr 长度超过 {$arg0} 字符（DoS 防御）
abac-expr-illegal-char = abac_expr 含策略终止符（疑似策略注入）
abac-expr-no-declaration = abac_expr 不允许声明 permit/forbid 策略
abac-expr-must-reference-context = abac_expr 必须引用 principal/resource/action 之一（拒绝纯字面量）
abac-engine-not-init = AbacEngine 未初始化，ABAC 校验失败（fail-closed）
abac-login-id-missing = ABAC 校验时未获取到 login_id
abac-policy-denied = ABAC 策略拒绝: action={$arg0}, resource={$arg1}

# credit
credit-alert-thresholds-empty = alert_thresholds 不能为空
credit-alert-thresholds-range = alert_thresholds[{$arg0}] = {$arg1} 超出范围 [0, 100]
credit-alert-thresholds-order = alert_thresholds 必须严格升序: {$arg0} <= {$arg1}

# web/cors
cors-credentials-wildcard = CORS 配置冲突：allow_credentials=true 时不允许 allowed_origins 包含通配符 "*"

# context/tenant
ctx-tenant-id-missing = X-Tenant-Id header 缺失

# response_parts 专用 message keys（不含 detail，用于 HTTP 响应体）
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
rate-limited-msg = 请求过于频繁，请稍后重试
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

# 密码策略规则消息（i18n 迁移）
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

# 会话劫持检测消息（i18n 迁移）
session-ip-mismatch = 会话 IP 不一致: 存储={$arg0}, 当前={$arg1}

# WAF 拦截原因消息（i18n 迁移）
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

# WAF 危险字符描述
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

# 同形异义字检测消息（i18n 迁移）
confusable-suggestion = 考虑用 '{$arg0}' 替换 '{$arg1}'

# OAuth2 PKCE / state / refresh 消息（i18n 迁移）
oauth2-pkce-length-invalid = code_verifier 长度必须在 43-128 之间，当前 {$arg0}
oauth2-pkce-chars-invalid = code_verifier 仅允许 [A-Z]/[a-z]/[0-9]/-/./_/~ 字符
oauth2-state-mismatch = state 参数不匹配，可能遭受 CSRF 攻击
oauth2-refresh-token-empty = refresh_token 不可为空

# 安全告警检测消息（i18n 迁移）
alert-ip-changed = IP 从 {$arg0} 变为 {$arg1}
alert-rapid-successive = {$arg0} 个 token 同时在线（阈值 {$arg1}）

# ABAC principal 校验消息（i18n 迁移）
abac-principal-control-char = login_id 包含控制字符

# Core 认证 / 权限消息（i18n 迁移）
core-switch-to-denied = switch_to 被拒绝：未配置 SwitchToGuard，默认 deny-all
core-switch-to-not-implemented = switch_to 未实现: {$arg0} 不支持身份切换
core-renew-not-implemented = renew_to_equivalent 未实现: {$arg0} 不支持 token 置换
core-account-no-permission = 账号 {$arg0} 未持有权限: {$arg1}
core-account-no-role = 账号 {$arg0} 未持有角色: {$arg1}
core-permission-name-empty = permission name 不能为空
core-permission-already-registered = permission 已注册: {$arg0}
core-permission-not-registered = 权限未在注册表中注册: {$arg0}

# Core token 风格消息（i18n 迁移）
core-token-parse-not-supported = {$arg0} token 风格不支持 parse（无 payload）
core-simple-secret-too-short = SimpleTokenStyle secret 长度必须 >= 32 字节（对齐 JWT 强校验）
core-simple-token-uuid-invalid = Simple token 格式错误：UUID 部分无效
core-simple-token-hmac-failed = Simple token HMAC 校验失败
core-simple-requires-feature = SimpleTokenStyle 需启用 secure-simple-token feature（A11 安全修复）

# DAO 未实现消息（i18n 迁移）
dao-not-implemented = {$arg0} 未实现：当前后端不支持

# 配置校验消息（i18n 迁移）
config-jwt-secret-empty = jwt_secret 不能为空（当 token_style=jwt 时）
config-jwt-algorithm-unsupported = 不支持的 jwt_algorithm: {$arg0}（仅支持 HS256/HS384/HS512）
config-jwt-secret-too-short = jwt_secret 长度不足：{$arg0}，实际 {$arg1} 字节——请用 `openssl rand -base64 48` 生成高熵密钥
config-jwt-secret-weak = jwt_secret 为弱密钥：{$arg0}；可预测密钥可被字典爆破，请用 `openssl rand -base64 48` 生成高熵密钥
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

# 会话搜索消息（i18n 迁移）
session-search-keyword-too-long = keyword 长度超限：{$arg0} > {$arg1}
session-search-size-exceeded = size 超限：{$arg0} > {$arg1}

# STP 模块消息（i18n 迁移）
stp-service-empty = service 参数不能为空
stp-not-implemented = {$arg0} 未实现

# 策略防火墙消息（i18n 迁移）
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

# Account 模块消息（i18n 迁移）
account-totp-parse-failed = TOTP secret_data 解析失败（期望 JSON 包含 secret/step/digits 字段）: {$arg0}
account-disable-service-colon = service 不能包含冒号（避免 key 注入）: {$arg0}
account-disable-login-id-colon = login_id 不能包含冒号（避免 key 注入）: {$arg0}

# Protocol 模块消息（i18n 迁移）
oidc-algorithm-unsupported = OidcHandler 仅支持 HS256/HS384/HS512 算法，当前算法不支持: {$arg0}
oidc-iss-mismatch = OIDC iss 不匹配: token 中的 issuer 与期望不符
oidc-aud-mismatch = OIDC aud 不匹配: token 中的 audience 不包含本客户端 client_id
temp-prefix-colon = prefix 不可包含 ':'
temp-ttl-invalid = ttl_seconds 必须大于 0
sso-secret-empty = SSO secret 不能为空（依据安全审计 M5：ticket 必须签名）

# Server / HTTP 层消息（i18n 迁移）
server-invalid-api-key = 无效的 API Key
server-prometheus-encode-failed = Prometheus 指标编码失败
server-internal-api-key-missing = internal_api_key 未配置，内网 API 将拒绝所有请求。请通过 with_internal_api_key() 设置非空值

# 剩余防火墙 / 账号 / OIDC / OTel 消息（i18n 迁移）
firewall-anomalous-need-login-id = AnomalousLogin 需要 login_id 但 ctx.login_id 为 None
firewall-ratelimit-user-none = RateLimit scope=User 但 ctx.login_id 为 None
firewall-ratelimit-tenant-none = RateLimit scope=Tenant 但 ctx.tenant_id 为 None
user-lockout-permanent = 用户 {$arg0} 已被永久锁定
user-lockout-temporary = 用户 {$arg0} 已被临时锁定，直到 {$arg1}
oidc-timeout-negative = timeout 不能为负数: {$arg0}
otel-exporter-failed = OTLP exporter 构造失败: {$arg0}
otel-provider-failed = Tracer provider 设置失败: {$arg0}

# 报告遗漏（config-load / dao-repo / cache / authflow / annotation）
config-rate-limit-backend-unsupported = GARRISON_RATE_LIMIT_BACKEND 不支持的值 '{$arg0}'，仅支持 'memory' 或 'redis'
dao-user-device-limit-exceeded = 用户（{$arg0}）设备数已达上限，最多 {$arg1}
cache-l1-ttl-must-positive = UserCacheService::new: l1_ttl_secs 必须 > 0
cache-l2-ttl-must-positive = UserCacheService::new: l2_ttl_secs 必须 > 0
authflow-required-action-not-implemented = RequiredAction 步骤在 v0.6.0 未实现
annotation-parse-failed = 无法从字符串解析注解（含数据变体需显式构造）: {$arg0}
stp-stateless-jwt-requires-revocation = token_style=jwt 且 jwt_mode=Stateless 时必须启用 enable_jwt_revocation（三选一：1) 开启 JWT 撤销黑名单 enable_jwt_revocation=true；2) 改用 JwtMode::Mixin；3) 显式风险接受开关 allow_stateless_jwt_no_revocation=true）
config-unknown-token-style-jwt = 不支持的 token_style: jwt（需启用 protocol-jwt feature）

# i18n 审计 2026-09：key:: 约定缺失的 FTL 消息补齐（P2）

# apikey
apikey-namespace-reserved = API Key 命名空间 '{$arg0}' 为保留名称
apikey-scope-not-allowed = API Key scope '{$arg0}' 不在允许范围内

# authflow
authflow-unknown-custom-condition = 未知自定义条件: {$arg0}
ip-whitelist-parse-failed = IP 白名单条目 '{$arg0}' 解析失败: {$arg1}

# limiteron 熔断器
circuit-open = 熔断器已打开: {$arg0}
circuit-limited = 熔断器限流拒绝请求: {$arg0}
circuit-breaker = 熔断器错误: {$arg0}

# core token
core-simple-token-no-sep = Simple token 格式错误：缺少单元分隔符

# credit 计量
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

# dao
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

# 密码策略 / HIBP
hibp-client-build-failed = HIBP 客户端构建失败: {$arg0}
hibp-http-status = HIBP 请求返回异常状态: {$arg0}, {$arg1}
hibp-request-failed = HIBP 请求失败: {$arg0}, {$arg1}
hibp-body-read-failed = HIBP 响应体读取失败: {$arg0}

# jwt
jwt-secret-too-short = jwt secret 长度不足: {$arg0}, {$arg1}
jwt-refresh-login-id-parse-failed = jwt refresh login_id 解析失败: {$arg0}, {$arg1}
jwt-refresh-cleanup-get-session = jwt refresh 清理：读取 session 失败: {$arg0}
jwt-refresh-cleanup-get-conn = jwt refresh 清理：获取连接失败: {$arg0}
jwt-refresh-cleanup-delete = jwt refresh 清理：删除失败: {$arg0}
jwt-revoked = JWT 已被吊销: {$arg0}

# limiteron
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

# manager
manager-active-timeout-overflow = active_timeout 溢出 u64: {$arg0}

# secure
secure-httpbasic-unsupported-scheme = HTTP Basic: 不支持的认证方案: {$arg0}
secure-httpdigest-unsupported-scheme = HTTP Digest: 不支持的认证方案: {$arg0}
secure-http-digest-missing-uri = HTTP Digest: 缺少 uri 参数

# sso / saml
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

# stp
stp-login-ip-blocked = 登录被拒绝：IP {$arg0} 已被封禁
stp-check-login-ip-blocked = 校验登录被拒绝：IP {$arg0} 已被封禁
stp-apikey-ip-blocked = API Key 请求被拒绝：IP {$arg0} 已被封禁
stp-simple-token-style-requires-secure-simple-token-feature = token_style=simple 需启用 secure-simple-token feature

# strategy / firewall
strategy-firewall-bruteforce-reason = 爆破封禁原因：尝试 {$arg0} 次超过上限 {$arg1}
strategy-firewall-bruteforce-locked = IP {$arg0} 因爆破已被封禁
strategy-firewall-bruteforce-blocked = 爆破拦截：IP {$arg0}, {$arg1}
strategy-firewall-ratelimit-blocked = 限流拦截：scope {$arg0}, {$arg1}
strategy-limiter-eval-lua = 限流器 eval_lua 失败: {$arg0}
strategy-ddos-global-blocked = DDoS 全局限流已超限（{$arg0} req/s）
strategy-ddos-ip-blocked = DDoS 单 IP 限流已超限：{$arg0}（{$arg1} req/s）
strategy-analyzer-shutdown-timeout = 异常分析器关闭超时: {$arg0}

# i18n 审计 2026-09：loc! 引用了不存在的 FTL 消息（P3）
alipay-response-missing-oauth-token-response = alipay 响应缺少 alipay_system_oauth_token_response 字段
alipay-response-missing-access-token = alipay 响应缺少 access_token 字段
session-kickout-password-changed = 密码已变更

# i18n 审计 2026-09：英文裸错误消息迁移到 key:: 约定（P1）
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

# P1 迁移过程中发现的额外英文裸消息
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
# OAuth2 token 端点错误（0.9.0 i18n 收口：错误码前缀保留 RFC 用语）

oauth2-rate-limited-client = rate_limited: 客户端请求过于频繁，请稍后再试
oauth2-client-id-missing = invalid_client: client_id 缺失（既未在 Authorization 头也未在 body 中提供）
oauth2-client-not-exist = invalid_client: client_id {$client_id} 不存在
oauth2-client-secret-mismatch = invalid_client: client_secret 不匹配
oauth2-grant-not-allowed-auth-code = unauthorized_client: 客户端未授权 authorization_code grant type
oauth2-code-param-missing = invalid_request: code 参数缺失
oauth2-code-verifier-missing = invalid_request: code_verifier 参数缺失（PKCE 强制）
oauth2-redirect-uri-param-missing = invalid_request: redirect_uri 参数缺失
oauth2-code-invalid-or-expired = invalid_grant: 授权码无效或已过期
oauth2-code-client-mismatch = invalid_grant: 授权码与 client_id 不匹配
oauth2-redirect-uri-mismatch = invalid_grant: redirect_uri 与授权时不一致
oauth2-pkce-verify-failed = invalid_grant: PKCE code_verifier 校验失败
oauth2-grant-not-allowed-refresh-token = unauthorized_client: 客户端未授权 refresh_token grant type
oauth2-refresh-token-param-missing = invalid_request: refresh_token 参数缺失
oauth2-refresh-token-invalid-or-expired = invalid_grant: refresh_token 无效或已过期
oauth2-rotated-token-validate-failed = rotate 后新 refresh_token validate 失败
oauth2-refresh-token-client-mismatch = invalid_grant: refresh_token 与 client_id 不匹配
oauth2-grant-not-allowed-client-credentials = unauthorized_client: 客户端未授权 client_credentials grant type
oauth2-grant-not-allowed-password = unauthorized_client: 客户端未授权 password grant type
oauth2-password-verifier-not-configured = unauthorized_grant_type: password grant type 未配置 PasswordVerifier
oauth2-username-param-missing = invalid_request: username 参数缺失
oauth2-password-param-missing = invalid_request: password 参数缺失
oauth2-rate-limited-user = rate_limited: 用户请求过于频繁，请稍后再试
oauth2-account-temp-locked = rate_limited: 账户已被临时锁定，请稍后再试
oauth2-invalid-credentials = invalid_grant: 用户名或密码错误

# ABAC 校验错误（0.9.0 i18n 收口）

abac-expr-too-long = abac_expr 长度超过 {$max} 字符（DoS 防御）
abac-expr-illegal-chars = abac_expr 含非法字符 `{"{"};{"}"}`（疑似策略注入）
abac-expr-policy-forbidden = abac_expr 不允许声明 permit/forbid 策略
abac-expr-must-reference-entity = abac_expr 必须引用 principal/resource/action 之一（拒绝纯字面量）
abac-engine-not-initialized = AbacEngine 未初始化，ABAC 校验失败（fail-closed）

# Backend / 宏 / 社交注册表 / SDForge（0.9.0 i18n 收口）

backend-remote-base-url-invalid-scheme = base_url 协议非法：{$arg0}（必须为 http:// 或 https://）
check-login-returned-false = 未登录（check_login 返回 false）
social-provider-name-invalid = 非法的社交登录 provider 名称：{$provider}
social-provider-not-registered = 社交登录 provider 未注册：{$provider}
caller-login-id-mismatch = caller_login_id 与 session.login_id 不匹配
metrics-encode-failed = Prometheus 指标编码失败

# Password reset（account-password-reset）
pwdreset-mail-subject = 密码重置请求
pwdreset-mail-body = 您请求了密码重置。请在 {$minutes} 分钟内使用以下一次性令牌完成重置：/reset-password?token={$token}

# OAuth2 authorize/resume 端点（0.9.0 i18n 收口）
oauth2-resume-ticket-missing = ticket 参数缺失

# 可观测性日志消息（tracing）国际化

logs-noop-sms-sender-send-code = NoopSmsSender 发送验证码（code 已省略）
logs-csrf-set-cookie-build-failed = CSRF Set-Cookie 构建失败，已跳过
logs-cors-allowlist-not-configured = frontend_separation CORS 未配置 cors_config.allowed_origins，任意 Origin 均被回显；建议配置允许列表以收紧信任边界
logs-cors-feature-disabled = frontend_separation CORS 回显任意 Origin（web-cors feature 未启用，无法按 cors_config.allowed_origins 过滤）；建议启用 web-cors 并配置允许列表
logs-cors-origin-not-allowed = Origin 未命中 CORS 允许列表，跳过 Allow-Origin 回显
logs-sso-oidc-jwks-fetch-retry = sso-oidc-jwks-fetch: 传输层错误，100ms 后重试: {$error}

# 可观测性日志消息（tracing）i18n —— r2 收口
# 补键：调用点已迁移到 translate_detail，但 en/zh 双包均缺键，日志直接打印原始 key
# （r2 迁移轮被中断所致）。

# OAuth2 back-channel logout 投递（backchannel-logout）
logs-backchannel-logout-drain-complete = backchannel-logout drain 完成
logs-backchannel-logout-drain-failed = backchannel-logout drain 失败（下轮重试）: {$error}
logs-backchannel-logout-max-ttl-retired = backchannel-logout 投递超过 MaxTtl，置 failed 退役（不再投递）
logs-backchannel-logout-delivery-retried = backchannel-logout 投递失败，计入重试

# 续签 token 写入响应（router）
logs-renewed-token-header-name-invalid = 续签 token 写入响应 header 失败：token_name 非法，已跳过
logs-renewed-token-header-value-invalid = 续签 token 写入响应 header 失败：token 含非法字符，已跳过
logs-renewed-token-cookie-value-invalid = 续签 token 写入 Set-Cookie 失败：cookie 串含非法字符，已跳过
logs-renewed-token-cookie-build-rejected = 续签 token 写入 Set-Cookie 失败：构建点校验拒绝，已跳过

# sdforge 内部路由（server）
logs-sdforge-token-info-cross-user = get_token_info 所有权校验失败：跨用户访问
logs-sdforge-session-cross-user = get_session 所有权校验失败：跨用户访问

# 安全告警（strategy::alert）
logs-alert-anomaly-login = 异常登录告警
logs-alert-new-device-login = 新设备登录告警
logs-alert-disable-triggered = 封禁触发告警
logs-alert-privilege-escalation = 权限提升告警
logs-alert-sensitive-operation = 敏感操作告警

# limiteron 封禁适配器
logs-limiteron-ban-record-parts-mismatch = limiteron-ban: 封禁记录段数不对，视为未封禁（fail-open）
logs-limiteron-ban-duration-parse-failed = limiteron-ban: 封禁记录 duration 字段解析失败，视为未封禁（fail-open）
logs-limiteron-ban-expires-at-parse-failed = limiteron-ban: 封禁记录 expires_at_ts 解析失败，视为未封禁（fail-open）
logs-limiteron-ban-times-parse-failed = limiteron-ban: 封禁记录 ban_times 解析失败，视为未封禁（fail-open）
logs-limiteron-ban-timestamp-invalid = limiteron-ban: 封禁记录时间戳非法，视为未封禁（fail-open）
logs-limiteron-ban-times-key-write-failed = limiteron-ban: 封禁次数 key 写入失败，回滚主记录
logs-limiteron-ban-history-key-write-failed = limiteron-ban: 封禁历史 key 写入失败，回滚主记录与次数
logs-limiteron-ban-cleanup-unimplemented = limiteron-ban: cleanup_expired_bans 未实现（GarrisonDao 无 iter API），返回 0——请勿依赖本方法清理过期封禁（TTL 自动过期 + is_banned 查询时检查兜底）
logs-limiteron-ban-list-unimplemented = limiteron-ban: list_bans 未实现（GarrisonDao 无 iter API），返回空列表——请勿依赖本方法做封禁审计/枚举（假阴性）

# Credit 计量（multi-tenant-credit-metering）
logs-credit-concurrent-over-limit-rollback = credit: 并发交错导致超限扣减，回滚本次消费
logs-credit-rolling-window-start-delete-failed = credit: Rolling 周期重置后删除 window_start 失败（best-effort，残留 key 由 TTL 过期或下次重置兜底）
logs-credit-decr-rollback-failed = credit: 回滚 decr 失败（best-effort，拒绝语义不受影响）
logs-credit-reset-consumed-delete-failed = credit: reset 删除 consumed key 失败（部分重置语义，剩余 key 不再删除）
logs-credit-reset-meta-delete-failed = credit: reset 删除 meta key 失败（部分重置语义，window_start 不再删除）
logs-credit-throttle-capacity-full = credit: 活跃度节流容量满，丢弃本次落库（窗口外重写）
logs-credit-throttle-write-failed = credit: 活跃度落库写失败（条目已清理，窗口外活跃度重新入队）
logs-credit-throttle-write-timeout = credit: 活跃度落库写超时（条目已清理，窗口外活跃度重新入队）
logs-credit-throttle-window-dropped = credit: 活跃度节流窗口内丢弃汇总（丢弃=跳过本次落库，窗口外重写）

# 指标注册（account / credit / observability）
logs-metrics-already-registered = {$arg0} 已注册到 prometheus 默认 registry（重复 new 或与 register_to 混用），返回未注册的本地实例；已注册实例不受影响

# Web 框架集成护栏
logs-actix-config-not-registered = GarrisonConfig 未注册为 actix app_data（web::Data<Arc<GarrisonConfig>>），auth extractor 回退 default_config；安全参数可能不一致，请通过 App::app_data(web::Data::new(Arc::new(config))) 显式注册
logs-actix-tenant-header-unverified = TenantContext 从客户端可控的 X-Tenant-Id header 提取租户且未与认证主体比对：任何调用方可声明任意租户 ID。本 extractor 仅做格式校验（数字解析），不做「主体→租户」归属授权。租户隔离请勿依赖该 header 值——应使用 ClaimTenantResolver（token claim）等服务端可信来源，或在业务层校验 principal 与租户的归属关系
logs-backend-remote-plaintext-http = BackendRemote base_url 使用明文 http://，X-API-Key 可能被网络路径窃听；生产环境应使用 https://
logs-router-invalid-path-protected = GarrisonRouter::route_protected 拒绝非法路径（必须非空且以 '/' 开头），该路由不会受鉴权保护
logs-router-duplicate-path-override = GarrisonRouter::route_protected 重复注册同一路径，原注解将被覆盖（last-wins）

# auth_server 启动配置（server::config）
logs-server-internal-api-key-too-short = server-internal-api-key-too-short: 内网 API Key 短于下限，1.0 将转为拒绝；请轮换为 ≥32 字节密钥
logs-server-external-login-unacknowledged = server-external-login-unacknowledged: 外网登录端点已暴露且未确认，1.0 将转为拒绝；请传入确认串 external_login_ack
logs-server-wildcard-bind-default = server-wildcard-bind-default: 未显式配置的通配绑定将在 1.0 变为回环，容器部署请显式 with_external_bind(0.0.0.0) / with_internal_bind(0.0.0.0)
logs-config-cors-wildcard-without-credentials = config security rules: cors allowed_origins=["*"] without allow_credentials — 任意源可读取响应，暴露敏感数据的部署应改为显式 origin 白名单

# CLI 帮助（garrison-cli，cli-ops feature）
cli-about = Garrison 运维工具

# 数据擦除残留处置提示（data-erasure）
compliance-erasure-residual-ip-artifacts = IP 关联的其他防护记录（GeoIP 缓存、限速窗口键）随 TTL 自然过期；若需立即清除请扩展本方法
compliance-erasure-residual-api-key = API Key：与 owner 关联且含业务授权语义，经 ApiKeyRepository 按 owner 查询后吊销（见 protocol-apikey 文档）
compliance-erasure-residual-audit-log = 审计日志：合规保留期优先于删除权（个保法第 47 条 / GDPR Art. 17(3)(b) 法律义务例外），到期按保留策略销毁
compliance-erasure-residual-business-data = 业务用户资料与业务副本：存储于业务方自有表，框架不可达
compliance-erasure-residual-verification-code = 验证码 / 邮箱验证记录：以手机号/邮箱为键（业务映射），随 TTL（≤1 小时）自然过期
compliance-erasure-residual-issued-jwt = 已发出的 JWT：无状态签名，到期前技术不可撤回（除非启用 revocation，见 config enable_jwt_revocation）

# i18n sweep 2026-10: hardcoded tracing / CLI / example strings wired to translate_detail

# Log messages (tracing) — account password reset
logs-pwdreset-mail-delivery-failed = 密码重置邮件投递失败
logs-pwdreset-history-append-replaced-generation-failed = 密码历史追加（替换代次）失败；当前代次的哈希可能对 HistoryRule 不可见
logs-pwdreset-history-append-and-rollback-failed = 密码历史追加失败且凭据回滚同样失败；凭据可能不一致

# Log messages (tracing) — config
logs-config-argon2-weak-params-accepted = password_hasher：argon2 m_cost {$cost} 低于 OWASP 下限 {$floor} KiB——已通过 allow_weak_argon2_params 显式接受弱参数（内存受限部署？）
logs-config-deprecated-key-migrated = 弃用配置键 "{$key}"（自 {$since}）已处理：{$outcome}；请在 1.0.0 前更新配置
logs-config-deprecated-key-unmigratable = 弃用配置键 "{$key}"（自 {$since}）已不可自动映射，1.0.0 将拒绝该键；{$guidance}
config-deprecation-guidance-delete = 请从配置中删除该键
config-deprecation-guidance-rename = 请手动重命名该键
logs-config-rate-limit-redis-feature-disabled = rate-limit-redis 特性未启用：限流仅按进程计数；多实例部署必须启用 rate-limit-redis 才能获得全局限额
logs-config-rate-limit-memory-backend = rate_limit_backend=Memory：限流仅按进程计数；多实例部署必须切换 Redis 获得全局限额
logs-config-rate-limit-redis-active = 限流后端已切换为 Redis：登录 hook 与 RateLimitStrategy 使用独立限流存储（会话/token 数据仍在原 DAO）
config-rate-limit-redis-connect = Redis 限流后端连接失败（阶段: {$stage}，端点: {$endpoint}，错误码: {$code}）
config-deprecation-slot-lock-poisoned = deprecation 槽位锁应可用
logs-cookie-same-site-none-without-secure = cookie SameSite=None 需要 Secure 上下文（cookie_secure=false）；已降级为 SameSite=Lax

# Log messages (tracing) — dao / cache / limiteron / audit
logs-dao-identifier-register-conflict-row-vanished = identifier register：租户内复查前唯一冲突行已消失，返回中性 Registered
logs-event-tx-dropped-without-commit = garrison-event-tx-dropped-without-commit：{$count} 条缓冲事件被丢弃，类型：[{$kinds}]，打开的事务经 dbnexus drop 级联回滚
logs-event-tx-discarded-after-commit-failure = garrison-event-tx-discarded-after-commit-failure：commit 返回 Err，{$count} 条缓冲事件未派发即丢弃，类型：[{$kinds}]
logs-event-tx-dispatch-cancelled-after-commit = garrison-event-tx-dispatch-cancelled-after-commit：commit 成功但派发 future 中途被取消，已派发 {$dispatched}/{$total} 条事件，其余未派发即丢弃，类型：[{$kinds}]
logs-error-rejection-rate-limited = garrison 拒绝：已触发限流
logs-limiteron-quota-consume-rollback-failed = 配额消费超限回滚失败
logs-audit-mask-metadata-invalid-json = 审计 mask_metadata：metadata 不是合法 JSON，已跳过掩码并保留原值
logs-cache-l3-write-back-failed = cache：L3 成功但写回失败，返回未缓存的值
logs-cache-chain-read-failed-evict-and-fallback = cache：链读/反序列化失败，逐出该键并回源 L3

# Log messages (tracing) — oauth2 / apikey
logs-oauth2-authorize-tenant-context-missing = oauth2 authorize：缺少租户上下文，回退默认租户 0（consent 记忆以默认租户为键）
logs-oauth2-refresh-rotation-not-configured = oauth2 refresh_token 轮换未配置：refresh grant 走 DAO 退化路径且无 reuse detection——被盗 refresh_token 重放不会触发链式撤销
logs-apikey-global-verify-enabled = apikey 全局校验已开启：verify() 可校验任意 namespace 的 key；租户隔离请优先使用 verify_with_namespace

# Log messages (tracing) — secure
logs-secure-rollback-hourly-window-counter-failed = 小时窗口计数回滚失败
logs-secure-rollback-daily-window-counter-failed = 天窗口计数回滚失败
logs-secure-rollback-window-counter-failed = {$label} 窗口计数回滚失败
logs-field-encryption-degenerate-non-primary-key = 字段加密：非主钥为退化密钥（单字节重复）；仅允许用于旧数据解密——请用 change-key 轮换掉

# Log messages (tracing) — server / http layer
logs-server-config-unrecognized-boolean = 无法识别的布尔值，回退默认值
logs-server-config-unrecognized-number = 无法识别的数值，回退默认值
logs-server-readiness-body-read-failed = readiness 探针：上游响应体读取失败
logs-server-readiness-body-not-json = readiness 探针：上游响应体不是合法 JSON
logs-server-apikey-auth-locked-window = API Key 认证已锁定：暴力破解锁定窗口生效中
logs-server-apikey-duplicate-header = 重复的 X-API-Key 头已拒绝
logs-server-apikey-auth-failed = API Key 认证失败
logs-server-apikey-auth-locked-out = API Key 认证已锁定
logs-server-inject-login-body-read-failed = inject_login_client_ip：请求体读取失败（超限或 IO 错误）
logs-server-sanitize-rejection-body-read-failed = sanitize_json_rejection：请求体读取失败
logs-server-oauth2-state-without-refresh-rotation = OAuth2State 构造时未注入 RefreshTokenRotation：/oauth2/token 的 refresh grant 走 DAO 退化路径且无 reuse detection——refresh_token 重放与链式撤销不可用；请注入 TokenHandler::with_refresh_rotation
logs-server-jwks-retention-zero-fallback = with_jwks_retention_secs(0) 会让 Passive 钥立即退役；回退默认 {$secs} 秒
logs-server-discovery-jwks-algorithms-failed = discovery 元数据 jwks algorithms 派生失败
logs-server-discovery-scopes-failed = discovery 元数据 scopes 派生失败
logs-server-jwks-document-build-failed = jwks keystore 文档构建失败
logs-sdforge-caller-login-id-missing = 缺少 caller_login_id：所有权校验为强制项，拒绝请求
logs-server-consent-reconcile-removed-orphans = oauth2 consent 启动期 reconcile：已移除指向已删除 client 的孤儿 consent 行
logs-server-consent-reconcile-no-orphans = oauth2 consent 启动期 reconcile：无孤儿行
logs-server-consent-reconcile-failed = oauth2 consent 启动期 reconcile 失败（fail-open）；孤儿行（若有）仍留在存储中——下次重启或调用 reconcile_consents 重试
logs-server-external-drain-timeout = 外网服务优雅停机超时，停止等待在途请求
logs-server-internal-drain-timeout = 内网服务优雅停机超时，停止等待在途请求
logs-tls-watcher-start-failed = TLS 证书监视器启动失败；证书热重载已禁用
logs-tls-certificate-reloaded = 文件变更后已重新加载 TLS 证书
logs-tls-certificate-reload-failed = TLS 证书重新加载失败；继续使用原证书
logs-tls-watcher-stopped = TLS 证书监视器已停止；证书热重载不再可用

# Log messages (tracing) — stp / strategy / web
logs-stp-password-lockout-reset-failed = 登录成功后的密码锁定清零失败（不影响登录结果）
logs-stp-password-account-locked = login_with_password：账号已锁定
logs-stp-password-lockout-check-failed = 密码锁定检查失败，降级放行（最终防线是密码校验）
logs-stp-password-lockout-record-failed = 密码锁定失败计数失败（不影响登录结果）
logs-stp-password-rehash-persist-failed = 密码重新哈希落盘失败（不影响登录结果）
logs-stp-role-union-get-role-list-failed = 角色并集缓存：get_role_list 失败，跳过（fail-open）
logs-stp-role-union-no-sql-backend = 角色并集缓存：DAO 无 SQL 后端，跳过
logs-stp-role-union-precompute-failed = 角色并集缓存预计算失败，跳过（fail-open）
logs-stp-role-union-write-failed = 角色并集缓存写入失败（fail-open）
logs-stp-role-union-serialize-failed = 角色并集缓存序列化失败（fail-open）
logs-stp-remember-me-disabled = 请求了 remember_me 但配置已禁用，使用默认超时
logs-stp-jti-blacklist-snapshot-read-failed = jti 黑名单快照读取失败；已撤销 token 可能在自然过期前仍然有效
logs-stp-invalidate-login-cache-logout-failed = invalidate_login_cache 失败（不影响登出结果）
logs-stp-invalidate-login-cache-kickout-failed = invalidate_login_cache 失败（不影响踢出结果）
logs-strategy-permission-cache-invalidate-failed = 登出时权限缓存失效失败（缓存将随 TTL 过期）
logs-strategy-role-cache-write-failed = 角色缓存写入失败（login_id={$login_id}, role={$role}）：{$error}
strategy-rate-limit-adaptive-config-invalid = rate_limit：AdaptiveThresholdConfig 非法：{$error}
logs-request-id-middleware-completed = request_id_middleware：请求处理完成
logs-warp-request-id-body-collect-failed = warp request_id：错误响应体收集失败

# Panic / expect invariant messages (fail-loud internal invariants)
mfa-hkdf-okm-len-static = 32 字节 OKM 在 HKDF-SHA256 输出上限内
mfa-webauthn-factor-registry-lock-poisoned = mfa webauthn factor 注册表锁不应中毒
cache-fallback-consumed-once = fallback 只被消费一次
cache-fallback-not-yet-executed = 错误发生在 fallback 之前，其尚未执行
jwt-refresh-grace-entries-lock-poisoned = grace_entries 锁不应中毒
secure-csprng-unavailable = OS CSPRNG 不可用
secure-aes-key-len-static = AES-256 密钥长度静态固定为 32 字节
secure-gcm-nonce-len-static = GCM nonce 长度静态固定为 12 字节
server-inject-login-client-ip-invariant = should_inject 蕴含 client_ip 存在

# HTTP response bodies (axum server middleware / sdforge routes)
server-http-body-invalid-json-msg = 请求体必须是合法 JSON
server-http-body-validation-failed-msg = 请求体未通过校验
server-http-body-too-large-msg = 请求体超出大小限制
sdforge-caller-login-id-required-msg = caller_login_id 为必填

# CLI (garrison-cli / garrison-healthcheck)
cli-field-encryption-feature-disabled = WARN: 已设置 GARRISON_FIELD_ENCRYPTION_KEYS，但未启用 field-encryption 特性；该值被忽略
cli-change-key-report =
    change-key 报告（tenant={$tenant}, batch={$batch_size}，非事务：行级原子，中断后用旧密钥重跑即可收敛）：
      scanned: {$scanned}
      reencrypted: {$reencrypted}
      legacy_plaintext_reencrypted: {$legacy_plaintext_reencrypted}
      legacy_key_migrated: {$legacy_key_migrated}
      skipped_current_key: {$skipped_current_key}
      failed: {$failed}
cli-change-key-failed-row = failed-row: {$row}
cli-change-key-empty-scan-warning =
    警告：scanned = 0。本部署的敏感键命名空间很可能无法通过 --db-url 访问
    （生产默认把 KV 存放在进程内 oxcache 中，外部进程不可见）。不要依据本次运行删除旧密钥。
cli-check-key-report =
    check-key 报告（tenant={$tenant}, pattern={$pattern}）：
      scanned: {$scanned}
      encrypted_ok: {$encrypted_ok}
      legacy_plaintext: {$legacy_plaintext}
      legacy_raw_key: {$legacy_raw_key}
      corrupt: {$corrupt}

      legacy 计数非零说明迁移未完成；请运行 change-key 收敛。
cli-check-key-corrupt-row = corrupt-row: {$row}
cli-check-key-empty-scan-hint =
    scanned = 0 通常说明本部署的 KV 数据无法通过 --db-url 访问
    （生产默认把 KV 存放在进程内 oxcache）；详见模块文档。
cli-vacuum-kv-report = 已清理过期 KV 行：{$count}
cli-vacuum-kv-swept = 已清扫遗留 raw 会话 key 行：{$count}

cli-one-time-access-token-issued =
    已为用户 '{$user}'（租户 {$tenant}）签发一次性访问令牌。

    token:
    {$token}

    过期时间: {$expires_at} (unix {$unix})

    一次性登记: app_user_ext 的 field_key = {$field_key}

    单次使用语义需要服务端接线：本框架不会自动消费登记行。你的登录路径必须
    用同一签名密钥校验该 token，并在创建会话前原子删除登记行
    （find_by_user_and_key + delete）；没有该接线时，该 token 只是可在 TTL 内
    重放的短期 bearer 凭据。为同一用户重新签发会替换登记行。
bin-healthcheck-failed = garrison-healthcheck: {$arg0}
bin-healthcheck-status = garrison-healthcheck: 127.0.0.1:{$arg0} 的 /healthz 返回非 2xx 状态码 {$arg1}

# Official examples (examples/)
example-apikey-handler-built = [1] ApiKeyHandler 构建完成（allow_global_verify=true，示例语义）
example-apikey-verify-nonexistent = verify("nonexistent-key") → Err(InvalidToken) ✓（全局 verify 已放开）
example-sso-envelope-consume = [验签] 订阅侧 verify_sso_message 消费信封:
example-sso-channel-message-count = channel 应收到两封消息
example-sso-envelope-verified = 验签通过（last_seq={$seq}），取回业务消息 = {$payload}
example-sso-replay-rejected = 重放同一封 → 拒绝（{$reason}）
example-sso-replay-not-rejected = 重放的信封消息应验签失败，实际取回: {$payload}
example-sso-bare-message-rejected = 裸消息（无信封）→ 拒绝（{$reason}）
example-sso-bare-message-not-rejected = 未封装的裸消息应被拒，实际取回: {$payload}

# i18n audit 2026-10: key:: convention keys referenced in code but missing from both bundles (P4 fill-up)
# 说明：审计清单中的 `waf-xxx-key` 是文档占位符（src/web/axum/waf.rs:49），不是真实 key，故无条目。
# 说明：`auth-server-bootstrap-proxies-empty-entry`、`auth-server-bootstrap-proxy-not-private`、
#       `auth-server-field-encryption-no-keys`、`pwdreset-policy-violated-current-password`
#       从审计 key 中拆出，使各条消息保持各自措辞。

# account
account-argon2-params = argon2 密码哈希失败：{$arg0}
account-argon2-pool-closed = argon2 哈希线程池已关闭
action-token-jti-invalid = 动作令牌的 jti 非法：{$arg0}
action-token-purpose-mismatch = 动作令牌用途不匹配：{$arg0}
credential-create-hash-gate = 凭据创建被存量哈希门禁拒绝：{$arg0}
credential-possible-compromise = 凭据可能已泄露：{$arg0}
credential-update-hash-gate = 凭据更新被存量哈希门禁拒绝：{$arg0}
credential-verify-blocking = 凭据校验失败（阻塞任务卸载）：{$arg0}
list-credentials = 凭据列表查询失败：{$arg0}
pwdreset-binding-missing = 密码重置会话绑定缺失
pwdreset-identifier-invalid = 密码重置标识非法（{$arg0}）
pwdreset-password-credential-missing = 该用户没有启用的密码凭据
pwdreset-policy-violated = 密码策略不满足：{$arg0}
pwdreset-policy-violated-current-password = 新密码不得与当前密码相同
pwdreset-restricted-endpoint-denied = 受限密码重置会话不可访问端点 '{$arg0}'
pwdreset-session-not-found = 密码重置会话不存在
pwdreset-session-subject-mismatch = 密码重置会话主体不匹配：session={$arg0}, token={$arg1}
pwdreset-subject-binding-mismatch = 密码重置主体绑定不匹配：token-sub={$arg0}, binding={$arg1}
pwdreset-system-clock = 系统时间错误：{$arg0}
pwdreset-tenant-binding-missing = 密码重置租户绑定缺失
pwdreset-tenant-mismatch = 密码重置令牌租户不匹配
pwdreset-token-consume-failed = 密码重置令牌消费失败（已使用或已过期）
pwdreset-ttl-negative = 密码重置 TTL 不能为负数：{$arg0}
pwdreset-ttl-overflow = 密码重置 TTL 超出 i64 范围：{$arg0}

# apikey
apikey-global-verify-disabled = 全局 API Key 校验已禁用；请改用 verify_with_namespace，或通过 with_allow_global_verify 显式放开

# auth server bootstrap (bin/auth_server)
auth-server-bootstrap = {$arg0} 的值非法：'{$arg1}'——要求 IPv4/IPv6 字面量（如 127.0.0.1 或 0.0.0.0）；GARRISON_TRUSTED_PROXIES 则要求逗号分隔的 IP 列表（如 10.0.0.1,127.0.0.1）
auth-server-bootstrap-proxies-empty-entry = GARRISON_TRUSTED_PROXIES 含空条目；要求逗号分隔的 IP 列表（如 10.0.0.1,127.0.0.1）
auth-server-bootstrap-proxy-not-private = 可信代理 {$arg0} 不是私有地址；可信代理必须是回环/RFC1918/link-local/IPv6 ULA（公网 IP 可在链路上被伪造）
auth-server-fatal = 致命错误：{$arg0}
auth-server-field-encryption = GARRISON_FIELD_ENCRYPTION_KEYS 条目非法 '{$arg1}'（{$arg0}）——要求逗号分隔的 key_id:hex64 条目
auth-server-field-encryption-no-keys = 未配置字段加密密钥：请设置 GARRISON_FIELD_ENCRYPTION_KEYS（key_id:hex64,...），或关闭 field-encryption 特性

# backchannel logout queue
backchannel-http-client = back-channel logout HTTP 客户端构建失败：{$arg0}
backchannel-queue-connection = back-channel logout 队列：获取连接失败：{$arg0}
backchannel-queue-count = back-channel logout 队列：计数查询失败：{$arg0}
backchannel-queue-find = back-channel logout 队列：待投递条目扫描失败：{$arg0}
backchannel-queue-get-session = back-channel logout 队列：获取会话失败：{$arg0}
backchannel-queue-missing-row = back-channel logout 队列：已认领的行已不存在：{$arg0}
backchannel-queue-parse-count = back-channel logout 队列：计数解析失败：{$arg0}
backchannel-queue-pending = back-channel logout 队列：待投递列表查询失败：{$arg0}

# cache
cache-l1-init = L1 缓存初始化失败：{$arg0}
garrison-dao-cache = DAO 缓存后端错误：{$arg0}
garrison-dao-cache-value-not-utf8 = DAO 缓存值不是合法 UTF-8：{$arg0}

# cli (garrison-cli)
cli-change-key-empty-scan = 拒绝报告成功：敏感键命名空间看似无法通过 --db-url 访问（scanned = 0）
cli-change-key-rows-failed = change-key 结束，存在需要处理的行：{$arg0}
cli-check-key-corrupt-rows = check-key 发现需要处理的行：{$arg0}
cli-check-key-empty-scan = 拒绝报告成功：敏感键命名空间看似无法通过 --db-url 访问（scanned = 0）；详见模块文档
cli-healthcheck-failed = 健康检查探测失败：{$arg0}
cli-healthcheck-join = 健康检查探测任务 join 失败：{$arg0}
cli-healthcheck-status = 127.0.0.1:{$arg0} 的 /healthz 返回非 2xx 状态码 {$arg1}
cli-key-source-missing = 请传入 --key 或设置 GARRISON_FIELD_ENCRYPTION_KEYS
cli-key-spec-empty-id = key_id 不能为空：{$arg0}
cli-key-spec-format = 期望 key_id:hex 形式，实际：{$arg0}
cli-key-spec-hex-invalid = 密钥 '{$arg0}' 的 hex 必须恰为 64 个十六进制字符（32 字节）
cli-key-specs-empty = 至少传入一个 --key key_id:hex
cli-keygen-csprng = 签名密钥生成失败（OS CSPRNG）：{$arg0}
cli-one-time-exp-out-of-range = 一次性令牌 exp 超出范围：{$arg0}
cli-one-time-jti-missing = 已签名令牌缺少 jti
cli-one-time-migrate = 数据库迁移失败：{$arg0}
cli-one-time-secret-empty = 签名密钥不能为空
cli-one-time-secret-missing = 请传入 --secret 或设置 GARRISON_JWT_SECRET
cli-one-time-ttl-invalid = TTL 非法：{$arg0}（{$arg1}）
cli-one-time-user-not-active = 用户 '{$arg0}' 的状态为 {$arg1}（仅活跃用户可签发一次性凭据）
cli-one-time-user-not-found = 租户 {$arg1} 中不存在用户 '{$arg0}'
cli-runtime-build = tokio runtime 构建失败：{$arg0}
cli-user-hash-password-empty = 密码不能为空
cli-user-hash-password-missing = 请传入 --password 或设置 GARRISON_CLI_PASSWORD
cli-user-hash-user-colon = 用户名不得包含 ':'
cli-user-hash-user-empty = 用户名不能为空

# config
config-csrf-enabled-unsupported = csrf_enabled 值不支持：{$arg0}（允许 true/false，不区分大小写）
config-jwks-retention-must-positive = jwks_retention_secs 必须为正数
config-jwt-key-missing = 配置中缺少 JWT 密钥：{$arg0}
config-jwt-key-multiple-types = JWT 密钥不得同时配置多种类型
config-jwt-key-unexpected-for-hs = HMAC 算法不应配置 JWT 密钥 '{$arg0}'
config-mfa-chain-factor-unknown = 未知的 MFA 链因子：{$arg0}
config-password-hash-algorithm-unsupported = 不支持的密码哈希算法：{$arg0}
config-password-hash-argon2-m-below-floor = argon2 m_cost {$arg0} 低于 OWASP 下限；算法：{$arg1}
config-password-hash-argon2-param-invalid = argon2 参数非法：{$arg0}
config-password-hash-argon2-pool-size-out-of-range = argon2 pool_size 超出范围：{$arg0}
config-password-hash-bcrypt-cost-out-of-range = bcrypt cost 超出范围：{$arg0}
config-refresh-grace-max-uses-zero = refresh_grace_max_uses 必须 >= 1，实际：{$arg0}
config-refresh-grace-period-negative = refresh_grace_period_secs 不能为负数，实际：{$arg0}

# context
ctx-invalid-cookie-domain = cookie '{$arg0}' 的 domain 非法
ctx-invalid-cookie-max-age = cookie max-age 非法：{$arg0}
ctx-invalid-cookie-path = cookie '{$arg0}' 的 path 非法
ctx-invalid-cookie-same-site = cookie same_site '{$arg0}' 非法：期望 Lax/Strict/None

# dao
dao-app-password-history-append = app_password_history 追加失败：{$arg0}
dao-app-password-history-recent = app_password_history 最近记录查询失败：{$arg0}
dao-app-user-create-hash-gate = app_user 创建被存量哈希门禁拒绝：{$arg0}
dao-app-user-identifier-find-owner = app_user_identifier 查询归属失败：{$arg0}
dao-app-user-identifier-find-owner-in-tenant = app_user_identifier 租户内查询归属失败：{$arg0}
dao-app-user-identifier-register = app_user_identifier 注册失败：{$arg0}
dao-app-user-update-hash-gate = app_user 更新被存量哈希门禁拒绝：{$arg0}
dao-app-webauthn-credential-conflict-lookup = webauthn 凭据冲突查询失败：{$arg0}
dao-app-webauthn-credential-conflict-without-owner = webauthn 凭据冲突但归属行不存在：{$arg0}
dao-app-webauthn-credential-delete = webauthn 凭据删除失败：{$arg0}
dao-app-webauthn-credential-insert = webauthn 凭据写入失败：{$arg0}
dao-app-webauthn-credential-list = webauthn 凭据列表查询失败：{$arg0}
dao-app-webauthn-credential-not-found = webauthn 凭据不存在：{$arg0}
dao-app-webauthn-credential-query = webauthn 凭据查询失败：{$arg0}
dao-app-webauthn-credential-sign-count-regression = webauthn 签名计数回退：拒绝将计数回拨（{$arg0}）
dao-app-webauthn-credential-update = webauthn 凭据更新失败：{$arg0}
dao-app-webauthn-credential-update-probe = webauthn 凭据更新后复核失败：{$arg0}
dao-app-webauthn-credential-update-probe-empty = webauthn 凭据更新后复核未返回行
dao-app-webauthn-credential-update-probe-parse = webauthn 凭据更新后复核行解析失败：{$arg0}
dao-conformance = 构造 {$arg0} 失败
dao-webauthn-credential-parse-attestation = webauthn 凭据行解析失败（attestation）：{$arg0}
dao-webauthn-credential-parse-created = webauthn 凭据行解析失败（created）：{$arg0}
dao-webauthn-credential-parse-cred-id = webauthn 凭据行解析失败（cred_id）：{$arg0}
dao-webauthn-credential-parse-pk = webauthn 凭据行解析失败（public_key）：{$arg0}
dao-webauthn-credential-parse-sign-count = webauthn 凭据行解析失败（sign_count）：{$arg0}
dao-webauthn-credential-parse-tenant = webauthn 凭据行解析失败（tenant_id）：{$arg0}
dao-webauthn-credential-parse-updated = webauthn 凭据行解析失败（updated）：{$arg0}
dao-webauthn-credential-parse-user = webauthn 凭据行解析失败（user_id）：{$arg0}
dao-webauthn-credential-sign-count-range = webauthn sign_count 超出范围：{$arg0}
event-tx-begin = 事件事务开启失败：{$arg0}
event-tx-commit = 事件事务提交失败：{$arg0}
event-tx-execute = 事件事务执行失败：{$arg0}
event-tx-get-session = 事件事务获取会话失败：{$arg0}
event-tx-rollback = 事件事务回滚失败：{$arg0}
import-hash-argon2-format = argon2 哈希导入失败：params 段缺失或不完整
import-hash-argon2-m-cost = argon2 m_cost {$arg0} 超过导入上限 {$arg1}
import-hash-argon2-p-cost = argon2 p_cost {$arg0} 超过导入上限 {$arg1}
import-hash-argon2-t-cost = argon2 t_cost {$arg0} 超过导入上限 {$arg1}
import-hash-bcrypt-cost = bcrypt cost {$arg0} 超过导入上限 {$arg1}
import-hash-bcrypt-format = bcrypt 哈希导入失败：cost 段缺失或非法
import-hash-unsupported = 不支持的导入哈希算法：{$arg0}
legacy-key-migration = 该后端不支持旧密钥迁移（不支持 TTL 查询）

# jwt / jwks
jwks-clock-invalid = JWKS 状态时钟非法：{$arg0}
jwks-state-corrupt = JWKS 状态损坏：{$arg0}
jwks-state-serialize = JWKS 状态序列化失败：{$arg0}
jwt-ec-curve-missing = EC 密钥缺少曲线标识
jwt-ec-curve-unsupported = 不支持的 EC 曲线：{$arg0}
jwt-ec-key = EC 密钥构建失败：{$arg0}
jwt-ec-pem-invalid = EC PEM 解析失败：{$arg0}
jwt-ec-sec1-format = 期望 SEC1 格式的 EC 私钥
jwt-ed-key = Ed25519 密钥构建失败：{$arg0}
jwt-ed-pem-invalid = Ed25519 PEM 解析失败：{$arg0}
jwt-ed-seed-len = Ed25519 seed 长度非法
jwt-header-invalid = JWT header 非法：{$arg0}
jwt-jwks-symmetric = JWKS 导出不支持对称密钥
jwt-jwks-unsupported-alg = JWKS 导出不支持算法 {$arg0}
jwt-key-algorithm-mismatch = 密钥算法不匹配：key={$arg0}, alg={$arg1}
jwt-keystore-no-active-key = keystore 没有活跃密钥
jwt-kid-already-registered = kid '{$arg0}' 已注册
jwt-kid-retired = kid '{$arg0}' 已退役
jwt-kid-symmetric = kid 不得指向对称密钥
jwt-kid-unknown = 未知的 kid：{$arg0}
jwt-refresh-compensate-delete = refresh token 补偿删除失败：{$arg0}
jwt-refresh-compensate-restore = refresh token 补偿恢复失败：{$arg0}
jwt-refresh-count-empty = refresh token 计数链为空
jwt-refresh-insert-and-compensate-failed = refresh token 写入失败且补偿同样失败：{$arg0}, {$arg1}
jwt-refresh-insert-rolled-back = refresh token 写入已回滚：{$arg0}
jwt-refresh-reuse-rejected = refresh token 重放已拒绝：{$arg0}
jwt-rsa-key = RSA 密钥构建失败：{$arg0}
jwt-rsa-pem-invalid = RSA PEM 解析失败：{$arg0}
jwt-sign-claims = JWT claim 签名失败：{$arg0}
jwt-snapshot-kid-mismatch = 密钥快照 kid 不匹配：{$arg0} != {$arg1}
jwt-snapshot-multiple-active = 密钥快照存在多个活跃密钥：{$arg0}

# mfa
mfa-aal-out-of-range = aal 超出范围（{$arg1}），实际：{$arg0}
mfa-amr-method-unknown = 未知的 AMR 方法：{$arg0}（{$arg1}）
mfa-recovery-batch-size-invalid = 恢复码批量大小非法（{$arg1}），实际：{$arg0}
mfa-recovery-misuse-parse = 恢复码误用状态解析失败：{$arg0}
mfa-remember-secret-too-short = remember-me 密钥过短：{$arg0}（{$arg1}）
mfa-remember-sign = remember-me 令牌签名失败：{$arg0}
mfa-remember-ttl-overflow = remember-me TTL 超出 i64 范围：{$arg0}
mfa-webauthn-assertion-parse = webauthn 断言解析失败：{$arg0}
mfa-webauthn-factor-already-registered = webauthn 因子已注册
mfa-webauthn-factor-not-registered = webauthn 因子未注册
mfa-webauthn-subject-mismatch = webauthn 断言主体不匹配：asserted-for={$arg0}, session={$arg1}

# oauth2 server
oauth2-server-authorize-ticket-deserialize = authorize ticket 反序列化失败：{$arg0}
oauth2-server-jwks-retirement-conflict = 另一实例已轮换密钥集；退役推迟到该次轮换
oauth2-server-jwks-rotation-conflict = 另一实例已轮换密钥集；请重新加载并重试

# qrlogin
qrlogin-session-parse = 扫码登录会话解析失败：{$arg0}
qrlogin-session-serialize = 扫码登录会话序列化失败：{$arg0}
qrlogin-ticket-hmac-init = 扫码登录 ticket HMAC 初始化失败：{$arg0}

# secure
secure-field-encryption-change-key = change-key 批量大小必须大于 0
secure-field-encryption-config = 字段加密配置错误：{$arg0}
secure-field-encryption-dao = 敏感键命名空间操作被拒绝：{$arg0}
secure-field-encryption-decode = 字段解密失败：{$arg0}
secure-field-encryption-open = 字段解密失败：AAD、密钥或认证标签不匹配
secure-field-encryption-seal = 字段加密失败：{$arg0}
secure-field-encryption-utf8 = 字段值不是合法 UTF-8：{$arg0}
secure-limiter-refund = 限流器退还失败：{$arg0}
session-sim-primary-amr = 主 AMR 模拟失败：{$arg0}

# server
server-external-login-unacknowledged = 外网登录在非回环绑定上开启且未确认（{$arg0}）；请传入确认串 external_login_ack
server-internal-api-key-too-short = 内网 API Key 短于下限（{$arg0}）；请轮换为 ≥32 字节密钥

# sso
sso-client-secret-too-short = SSO 客户端密钥过短：{$arg0}, {$arg1}
sso-message-envelope-format = SSO 消息信封格式非法
sso-message-envelope-serialize = SSO 消息信封序列化失败：{$arg0}
sso-message-hmac-init = SSO 消息 HMAC 初始化失败：{$arg0}
sso-message-hmac-verify = SSO 消息 HMAC 校验失败
sso-message-seq-replay = SSO 消息序号重放已拒绝：{$arg0}, {$arg1}
sso-saml-audience-not-configured = 未配置 SAML audience；断言中的 audience：{$arg0}
sso-saml-destination-not-configured = 未配置 SAML destination；断言中的 destination：{$arg0}
sso-server-secret-too-short = SSO 服务端密钥过短：{$arg0}, {$arg1}

# stp
stp-check-disable-token-session-not-found = check_disable：未找到 token 会话
stp-check-login-session-tenant-unbound = check_login：存在租户上下文但会话无租户绑定
stp-check-login-tenant-mismatch = check_login：会话租户与请求租户不一致
stp-check-login-tenant-unbound = check_login：存在租户上下文但 token 无租户绑定
stp-login-id-control-char = login_id 不得包含控制字符
stp-login-id-sep = login_id 不得包含单元分隔符（U+001F）
stp-login-id-too-long = login_id 过长：{$arg0} 字节（上限 {$arg1}）
stp-login-id-whitespace = login_id 不得包含空白字符
stp-password-account-locked = 账号已锁定：{$arg0}
stp-password-lock-check = 密码锁定检查失败：{$arg0}
stp-password-lock-incr = 密码锁定失败计数递增失败：{$arg0}
stp-password-lock-set = 密码锁定状态写入失败：{$arg0}
stp-refresh-token-revoked = refresh token 已被撤销
stp-secondary-check-not-login = 二级校验要求已登录会话
strategy-sliding-window-count-parse = 滑动窗口计数解析失败：{$arg0}
strategy-sliding-window-key-empty = 滑动窗口 key 不能为空
strategy-sliding-window-response-length = 滑动窗口脚本返回的响应长度异常

# webauthn
webauthn-attestation-format = attestation 对象格式非法：{$arg0}
webauthn-ceremony = webauthn 仪式失败：{$arg0}
webauthn-challenge-conflict = challenge 键已被占用：{$arg0}
webauthn-challenge-deserialize = challenge 反序列化失败：{$arg0}
webauthn-challenge-encode = challenge 编码失败：{$arg0}
webauthn-challenge-getdel = challenge 消费（GETDEL）失败：{$arg0}
webauthn-challenge-serialize = challenge 序列化失败：{$arg0}
webauthn-challenge-setifabsent = challenge 写入（SETNX）失败：{$arg0}
webauthn-cred-id-encode = 凭据 ID 编码失败：{$arg0}
webauthn-cred-row-encode = 凭据行编码失败：{$arg0}
webauthn-cred-row-format = 凭据行格式非法：{$arg0}
webauthn-cred-row-identity-mismatch = 凭据行身份不匹配（credential_id={$arg0}）
webauthn-cred-row-parse = 凭据行解析失败：{$arg0}
webauthn-issuer-host-missing = issuer 缺少 host：{$arg0}
webauthn-issuer-invalid = issuer 非法：{$arg0}
webauthn-rp-build = relying party 构建失败：{$arg0}
webauthn-rp-mismatch = relying party 不匹配：{$arg0}
clientdata-parse = clientDataJSON 解析失败：{$arg0}
clientdata-utf8 = clientDataJSON 不是合法 UTF-8：{$arg0}
cred-id = 凭据 ID 解码失败：{$arg0}
start-auth = webauthn 认证发起失败：{$arg0}
start-register = webauthn 注册发起失败：{$arg0}
update-state = webauthn 状态更新失败：{$arg0}

# misc
warp-body-collect-failed = warp request_id：错误响应体收集失败

# DAO 契约测试套件（dao::testing，`testing` feature——下游自定义后端复用同一套契约测试）
# 断言消息保持原样（测试诊断文案，与仓库测试代码惯例一致）；panic/expect 失败路径与标签走 FTL。
dao-conformance-expect-ok-failed = [{$prefix}] {$what} 不应失败：{$error}
dao-conformance-expect-err-failed = [{$prefix}] {$what}，实际：{$actual}
dao-conformance-what-set-overwrite = set（覆盖）
dao-conformance-what-get-missing-key = get（缺键）
dao-conformance-what-delete-missing-key = delete（缺键）
dao-conformance-what-get-with-ttl-missing-key = get_with_ttl（缺键）
dao-conformance-what-incr-new-key = incr（新键）
dao-conformance-what-incr-increment = incr（续增）
dao-conformance-what-decr-missing-key = decr（缺键）
dao-conformance-what-decr-zero = decr（存量值 0）
dao-conformance-what-caui-missing-key = compare_and_update_if_greater（缺键）
dao-conformance-what-caui-smaller-value = compare_and_update_if_greater（更小值）
dao-conformance-what-get-old-key = get（旧键）
dao-conformance-what-get-new-key = get（新键）
dao-conformance-what-sia-new-key = set_if_absent（新键）
dao-conformance-what-sia-existing-key = set_if_absent（已存在键）
dao-conformance-what-gd-missing-key = get_and_delete（缺键）
dao-conformance-what-cas-mismatch = compare_and_swap（期望值不匹配）
dao-conformance-what-cas-match = compare_and_swap（期望值匹配）
dao-conformance-what-cas-missing-key = compare_and_swap（缺键）
dao-conformance-what-keys-single-char = keys（'?' 单字符模式）
dao-conformance-what-keys-no-match = keys（无匹配）
dao-conformance-what-keys-after-delete = keys（delete 之后）
dao-conformance-what-keys-after-rename = keys（rename 之后）
dao-conformance-what-vacuum-drain = vacuum（drain 预清宿主过期行）
dao-conformance-what-vacuum = vacuum（主清理）
dao-conformance-what-vacuum-2nd = vacuum（二次幂等）
dao-conformance-expect-err-update-missing-key = update 缺键应返回 Err(Dao)
dao-conformance-expect-err-expire-missing-key = expire 缺键应返回 Err(Dao)
dao-conformance-expect-err-incr-non-numeric = 非数值值 incr 应返回 Err(Dao)，禁止静默归零
dao-conformance-expect-err-incr-overflow = u64 溢出应返回 Err(Dao)
dao-conformance-expect-err-caui-non-numeric = 非数值值 compare_and_update_if_greater 应返回 Err(Dao)
dao-conformance-expect-err-rename-missing-key = rename 缺键应返回 Err(InvalidParam)（trait 文档契约）
dao-conformance-concurrent-sia-join-failed = [{$prefix}] set_if_absent 任务 join 失败
dao-conformance-concurrent-sia-error = [{$prefix}] set_if_absent 并发不应返回错误：{$error}
dao-conformance-concurrent-gd-join-failed = [{$prefix}] get_and_delete 任务 join 失败
dao-conformance-concurrent-gd-error = [{$prefix}] get_and_delete 并发不应返回错误：{$error}
dao-conformance-concurrent-incr-join-failed = [{$prefix}] incr 任务 join 失败
dao-conformance-concurrent-incr-error = [{$prefix}] incr 并发不应返回错误：{$error}
dao-conformance-concurrent-decr-join-failed = [{$prefix}] decr 任务 join 失败
dao-conformance-concurrent-decr-error = [{$prefix}] decr 并发不应返回错误：{$error}
dao-conformance-concurrent-caui-join-failed = [{$prefix}] compare_and_update_if_greater 任务 join 失败
dao-conformance-concurrent-caui-error = [{$prefix}] compare_and_update_if_greater 并发不应返回错误：{$error}
dao-conformance-concurrent-cas-join-failed = [{$prefix}] compare_and_swap 任务 join 失败
dao-conformance-concurrent-cas-error = [{$prefix}] compare_and_swap 并发不应返回错误：{$error}
dao-conformance-get-session-failed = [{$prefix}] get_session 不应失败：{$error}
dao-conformance-connection-failed = [{$prefix}] connection 不应失败：{$error}
dao-conformance-query-failed = [{$prefix}] 查询不应失败：{$error}
dao-conformance-query-returned-no-row = [{$prefix}] 查询应有结果行：{$sql}
dao-conformance-val-column-read-failed = [{$prefix}] val 列读取失败：{$error}
dao-conformance-execute-failed = [{$prefix}] execute 不应失败：{$error}
dao-conformance-injection-expected-dao-error = [{$prefix}] 注入失败应返回 Dao 错误，实际：{$actual}
dao-conformance-duplicate-binding-expected-already-bound = [{$prefix}] 重复绑定应返回 AlreadyBound，实际：{$actual}
dao-conformance-bound-credential-not-found = [{$prefix}] 已绑定凭据应可查得，实际：{$actual}
dao-conformance-query-must-succeed = [{$prefix}] 查询不应失败
dao-conformance-credential-update-must-succeed = [{$prefix}] 更新既有凭据应成功
dao-conformance-credential-must-exist-after-update = [{$prefix}] 更新后凭据应仍存在
dao-conformance-credential-must-exist-after-rollback = [{$prefix}] 回退拒绝后凭据应仍存在
dao-conformance-unbind-must-succeed = [{$prefix}] 解绑应成功
dao-conformance-unbind-must-be-idempotent = [{$prefix}] 重复解绑应幂等 Ok
cli-healthcheck-healthy = 健康：127.0.0.1:{$port} 的 /healthz 返回 {$code}
