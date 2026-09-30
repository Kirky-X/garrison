# Docker 交付物

容器镜像与编排文件集中在本目录。**构建上下文始终是仓库根**（`.dockerignore`
与 `Cargo.lock` 在根），因此 `.dockerignore` 留在仓库根而不随本目录移动——
BuildKit 从 context 根读取 ignore 规则，移走会导致 `target/` 等被排除项进入
上下文（构建变慢且缓存失真）。

## 文件

| 文件 | 用途 |
|------|------|
| `Dockerfile` | debian-slim 变体（默认推荐：可 shell 调试，自带 ca-certificates） |
| `Dockerfile.distroless` | distroless 变体（最小攻击面：无 shell / 包管理器；healthcheck 用镜像内探针二进制绝对路径） |
| `docker-compose.example.yml` | 单机部署最小可运行示例（fail-loud API Key 校验 + healthcheck + 可选 Redis 注释块）；`build.context: ..` 指向仓库根 |
| `docker-compose.e2e.yml` | E2E / 集成测试外部依赖编排（postgres:16-alpine、redis:7-alpine、Keycloak 26） |

## 构建

```bash
# debian-slim（构建上下文 = 仓库根）
docker build -f docker/Dockerfile -t garrison-auth:local .

# distroless
docker build -f docker/Dockerfile.distroless -t garrison-auth:distroless .
```

compose 示例从仓库根运行：

```bash
docker compose -f docker/docker-compose.example.yml up -d
```

变体选型、供应链风险与运维细节见 [DEPLOYMENT.md](../docs/DEPLOYMENT.md)「Docker 部署」节。
