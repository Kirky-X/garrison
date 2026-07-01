# Summary

# 介绍

- [Bulwark 简介](./README.md)

# 快速开始

- [入门指南](./getting-started.md)
- [配置参考](./configuration.md)

# 架构设计

- [整体架构](./architecture.md)
- [双抽象层（oxcache + dbnexus）](./abstraction-layers.md)
- [插件系统](./plugin-system.md)

# 功能域

- [登录认证与会话管理](./auth-session.md)
- [权限与角色（RBAC）](./permission-rbac.md)
- [协议层（JWT/OAuth2/SSO/Sign/APIKey/Temp）](./protocols.md)
- [安全模块（TOTP/Basic/Digest）](./secure-modules.md)

# Web 框架适配

- [axum 适配](./web-axum.md)
- [actix-web 适配](./web-actix.md)
- [warp 适配](./web-warp.md)

# 可观测性（0.3.0 新增）

- [Prometheus 指标](./observability-metrics.md)
- [结构化 JSON 日志](./observability-logs.md)
- [OpenTelemetry 分布式追踪](./observability-traces.md)

# 生态集成（0.3.0 新增）

- [gRPC 鉴权拦截器](./grpc.md)
- [异常消息 i18n](./i18n.md)
- [防火墙安全钩子](./firewall.md)

# 运维与部署

- [部署指南](./deployment.md)
- [开发指南](./development.md)
- [故障排查](./troubleshooting.md)

# 附录

- [版本路线图](./roadmap.md)
- [FAQ](./faq.md)
- [安全策略](./SECURITY.md)
- [贡献指南](./CONTRIBUTING.md)
