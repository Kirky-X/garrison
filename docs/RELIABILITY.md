# 可靠性验证指南（Redis 故障演练）

Garrison 的会话/缓存链路支持 Redis 后端（`cache-redis` / `rate-limit-redis`）。
本文档记录 Redis 故障演练的执行方法、预期行为与判读标准，用于发布前的可靠
性验证与客户环境的故障演练基线。

> 关联：[SECURITY.md](../SECURITY.md)｜[CONFIGURATION.md](./CONFIGURATION.md)｜[THREAT.md](./THREAT.md)

## 1. 覆盖场景

| # | 场景 | 故障注入 | 模拟的真实故障 |
|---|------|----------|----------------|
| 1 | 容器暂停 → 恢复 | `docker pause` / `unpause` | 宿主机内存压力 / OOM 冻结 / 虚拟机挂起 |
| 2 | 网络断开 → 重连 | `docker network disconnect` / `connect` | 交换机故障 / 安全组误封 / 跨可用区网络分区 |
| 3 | 强制重启 | `docker restart` | Redis 崩溃 / 内核升级重启 / 容器编排重新调度 |
| 4 | Sentinel 主从故障切换 | `docker pause` 主库（chaos profile：master/replica/sentinel） | 主库宕机后 Sentinel 自动提升副本、旧主恢复后降级回切 |

三场景覆盖两类典型故障形态：**进程级故障**（暂停/重启——连接悬挂或重置）
与**网络级故障**（解绑——进程存活但不可达）。后者更隐蔽：TCP 连接可能被
docker userland proxy 代答，脚本统一以**协议级 PING 响应**判定可用性，不以
"能否建立 TCP 连接"为准。

## 2. 执行方法

### 2.1 前置条件

- Docker 可用，`docker-compose.e2e.yml` 的 Redis 服务已拉起：

  ```bash
  docker compose -f docker-compose.e2e.yml up -d redis
  ```

- 无宿主 redis-cli 依赖：容器内探测经 `docker exec`，宿主侧探测用 bash
  `/dev/tcp` 发送 RESP 协议 `PING`。

### 2.2 运行

```bash
scripts/chaos_redis.sh            # 全部四场景（默认）
scripts/chaos_redis.sh pause      # 仅场景 1
scripts/chaos_redis.sh disconnect # 仅场景 2
scripts/chaos_redis.sh restart    # 仅场景 3
scripts/chaos_redis.sh sentinel   # 仅场景 4（自动拉起 chaos profile 演练拓扑）
```

环境变量可覆盖目标：`GARRISON_CHAOS_CONTAINER`（默认
`garrison-e2e-redis`）、`GARRISON_CHAOS_HOST`（默认 `127.0.0.1`）、
`GARRISON_CHAOS_PORT`（默认 `16379`）、`GARRISON_CHAOS_TIMEOUT_S`
（单次探测超时，默认 3 秒）。

脚本在注入前预置**金丝雀值**并在恢复后断言（场景 3 验证 `/data` 卷持久化
——重启不丢数据）；中断时经 `trap` 兜底解除暂停，不留 paused 遗留状态。

### 2.3 输出与退出码

- 每步输出 `[PASS]` / `[FAIL]` 行；任一场景失败使脚本退出码为 `1`。
- 全部通过时退出码 `0`。

## 3. 预期行为与判读标准

### 3.1 故障注入期（降级行为观测）

| 判读项 | 标准 |
|--------|------|
| 注入生效 | 场景内宿主侧协议 PING 无响应（脚本自动断言） |
| 场景 2 隔离形态 | 容器内 `redis-cli ping` 仍为 PONG（进程存活，仅网络隔离） |
| 应用侧缓存操作 | 不得 panic、不得无限阻塞工作线程；操作以错误返回或超时收场 |
| 应用侧会话/鉴权路径 | 缓存不可用期间读路径回源 DAO（性能下降但功能可用）；写路径按配置降级或报错，不得静默丢弃凭据类数据 |
| 观测手段 | garrison / oxcache 的 `tracing` 日志（连接错误、超时、回源记录）与指标（缓存命中率下降、错误计数上升） |

### 3.2 故障解除后（恢复验证）

| 判读项 | 标准 |
|--------|------|
| 容器健康 | 60 秒内回到 `health=healthy`（脚本自动断言，2 秒轮询） |
| 故障切换（场景 4） | 复本在 120 秒内被 Sentinel 提升为主（sdown→选举→提升全链路）；提升节点可写；**切换前经复制确认的金丝雀值可读**（脚本先等复制到达再注入故障，消除异步复制竞态）；旧主库恢复后 60 秒内被降级为副本重新入列 |
| 协议可用 | `PING → PONG`；`SET`/`GET` 往返成功（脚本自动断言） |
| 数据持久化 | 场景 3 金丝雀值跨重启保留（`/data` 卷生效；脚本自动断言） |
| 应用侧重连 | 缓存/限速客户端自动重建连接池，无需应用重启；日志中出现重连成功记录，命中率回升 |
| 数据一致性 | 重启恢复后 garrison 会话仍可经 DAO 校验（缓存是加速层，非唯一事实源；以 DAO 为准的路径不受缓存重启影响） |

### 3.3 判读口径说明

脚本层自动断言覆盖**基础设施可用性**（注入生效 + 恢复 + 持久化 + Sentinel
自动切换）；**应用层降级语义**（3.1 后四行）需在演练同时运行接入 garrison 的
应用实例并观测其日志/指标——判读标准如上表。Cluster 分片迁移仍不在脚本范围，
需独立演练环境。

> **演练拓扑与生产差异**：场景 4 使用单 Sentinel + quorum 1（compose
> `chaos` profile，提速与资源考虑）。生产部署至少 3 Sentinel + quorum 2——
> 单 Sentinel 无法形成选举多数派的安全性，生产判读时应按生产拓扑重演。

## 4. 环境适配

脚本默认面向 `docker-compose.e2e.yml` 的单机 Redis。接入客户环境时：

1. `GARRISON_CHAOS_*` 环境变量指向目标实例（容器编排环境需将
   `docker exec` / `network` 操作替换为对应编排平台的等价指令）；
2. 客户为金融/政务行业时，建议由客户或测评机构**现场见证**演练并留存
   报告（自测报告的效力边界见 [SECURITY.md](../SECURITY.md) 供应链章节）。
