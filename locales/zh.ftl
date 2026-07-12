# Bulwark 异常消息中文翻译（默认语言）
# 依据 spec exception-i18n 与 PRD 0.3.0 异常消息国际化

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
