# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0

# Garrison Auth Server 容器镜像（debian-slim 变体）。
#
# 三阶段（cargo-chef 依赖缓存）：
#   planner  生成 recipe.json（依赖清单，不含源码实现体）
#   builder  cook 预编译依赖（缓存命中时增量编译仅业务代码）→ 编译 release 二进制
#   runner   debian:bookworm-slim + 非 root 运行 + 内置 healthcheck 探针
#
# 构建示例：
#   docker build \
#     --build-arg VERSION=0.9.0-rc.2 \
#     --build-arg GIT_SHA=$(git rev-parse HEAD) \
#     -t garrison-auth:local .
#
# feature 门禁（对齐 Cargo.toml [[bin]] required-features，保持最小依赖面）：
#   auth-server + cache-memory  auth_server 的 required-features
#   server-health-check         /healthz liveness 探针路由（HEALTHCHECK 依赖）
#   tracing-log                 stdout 结构化 JSON 日志
#   不用 full/production：会拉入 bin 不消费的 db-postgres/cedar 等重依赖；
#   需要更强 feature 面时覆盖：--build-arg FEATURES=production

# 在 chef 基座层补装 stable（对应仓库 rust-toolchain.toml 的 channel 声明），
# 将工具链安装固定在 chef 缓存层——planner/builder 共享该层、不逐阶段重装；
# --profile minimal 跳过 rust-docs 等组件，省数百 MB
ARG CHEF_IMAGE=lukemathwalker/cargo-chef:latest-rust-1
FROM ${CHEF_IMAGE} AS chef
WORKDIR /app
RUN rustup toolchain install stable --profile minimal

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# sdforge build script 需要 protoc
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
# FEATURES 声明置于 apt 层之后、cook 之前：feature 变更不连带重跑 apt 层
# （ARG 在使用前声明即可）
ARG FEATURES=auth-server,cache-memory,server-health-check,tracing-log
COPY --from=planner /app/recipe.json recipe.json
# Cargo.lock 必须先于 cook 就位：--locked 要求锁文件存在，且保证预编译的
# 依赖版本与最终 build 完全一致（依赖缓存才有效）
COPY --from=planner /app/Cargo.lock Cargo.lock
RUN cargo chef cook --release --locked --recipe-path recipe.json \
    --features "${FEATURES}" --bin auth_server --bin garrison-healthcheck
COPY . .
RUN cargo build --release --locked --features "${FEATURES}" \
    --bin auth_server --bin garrison-healthcheck

FROM debian:bookworm-slim AS runner
ARG VERSION=dev
ARG GIT_SHA=unknown
# 版本仅落 OCI labels：garrison 无运行时版本端点，不做伪注入
LABEL org.opencontainers.image.title="garrison" \
    org.opencontainers.image.description="Garrison - 面向 Rust 生态的一站式身份认证鉴权框架（Auth Server 镜像）" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.source="https://github.com/Kirky-X/garrison" \
    org.opencontainers.image.documentation="https://docs.rs/garrison" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${GIT_SHA}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --no-create-home garrison \
    && ln -s /app/garrison-healthcheck /usr/local/bin/garrison-healthcheck

WORKDIR /app
COPY --from=builder /app/target/release/auth_server /app/target/release/garrison-healthcheck /app/

USER 1000
EXPOSE 8080 8081
# 探测本容器外网端口的 sdforge liveness 探针（恒 200）；目标端口随
# GARRISON_EXTERNAL_PORT 环境变量自动对齐（见 src/bin/garrison-healthcheck.rs）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/garrison-healthcheck"]
ENTRYPOINT ["/app/auth_server"]
