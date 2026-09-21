#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# Redis 故障演练脚本（四场景）：容器暂停恢复 / 网络断开重连 / 强制重启 /
# Sentinel 主从故障切换（chaos profile）。
#
# 基于 docker-compose.e2e.yml 的现有 Redis 服务（容器名 garrison-e2e-redis，
# 宿主端口 16379）。每场景依次：
#   1. 注入故障 → 确认不可用（降级行为可观测）
#   2. 解除故障 → 验证恢复（PING + SET/GET 往返 + 金丝雀值断言）
# 任何场景失败以 [FAIL] 标注并使脚本退出码为 1。
#
# 用法：
#   docker compose -f docker-compose.e2e.yml up -d redis   # 先拉起 Redis
#   scripts/chaos_redis.sh                                  # 全部三场景
#   scripts/chaos_redis.sh pause|disconnect|restart|sentinel # 单场景
#
# 环境变量：
#   GARRISON_CHAOS_CONTAINER  目标容器（默认 garrison-e2e-redis）
#   GARRISON_CHAOS_HOST       宿主探测地址（默认 127.0.0.1）
#   GARRISON_CHAOS_PORT       宿主探测端口（默认 16379）
#   GARRISON_CHAOS_TIMEOUT_S  单次探测超时秒数（默认 3）

set -u

CONTAINER="${GARRISON_CHAOS_CONTAINER:-garrison-e2e-redis}"
HOST="${GARRISON_CHAOS_HOST:-127.0.0.1}"
PORT="${GARRISON_CHAOS_PORT:-16379}"
TIMEOUT_S="${GARRISON_CHAOS_TIMEOUT_S:-3}"
CANARY_KEY="garrison:chaos:canary"
CANARY_VALUE="chaos-$(date +%s)"

FAILED=0

log()  { printf '%s\n' "$*"; }
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILED=1; }
step() { printf '  [ .... ] %s\n' "$*"; }

# 容器内 redis-cli（无宿主 redis-cli 依赖）
in_redis() { docker exec "$CONTAINER" redis-cli --no-auth-warning "$@" 2>/dev/null; }

# 宿主侧 TCP 可达性探测（不依赖宿主 redis-cli）：/dev/tcp 连接 + 超时
host_tcp_ok() {
  timeout "$TIMEOUT_S" bash -c "exec 3<>/dev/tcp/${HOST}/${PORT}" 2>/dev/null
}

# 宿主侧协议级可用性探测：发送 PING 并等待 +PONG。
# 仅测 TCP 连接不够——docker userland-proxy 会先替容器接受连接（disconnect 后
# 仍"连接成功"），必须以协议响应判定真实服务可用性。
host_redis_ping_ok() {
  timeout "$TIMEOUT_S" bash -c "
    exec 3<>/dev/tcp/${HOST}/${PORT}"' || exit 1
    printf "PING\r\n" >&3
    head -c 7 <&3
  ' 2>/dev/null | grep -q '^+PONG'
}

# 宿主侧必须不可用（故障注入生效的证据）
host_redis_down() {
  ! host_redis_ping_ok
}

wait_healthy() {
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    local health
    health="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo unknown)"
    if [[ "$health" == "healthy" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

preflight() {
  log "=== Redis 故障演练预检 ==="
  command -v docker >/dev/null || { fail "docker 不可用"; exit 1; }
  docker inspect "$CONTAINER" >/dev/null 2>&1 || { fail "容器 ${CONTAINER} 不存在（先 docker compose -f docker-compose.e2e.yml up -d redis）"; exit 1; }
  local state
  state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER")"
  [[ "$state" == "running" ]] || { fail "容器状态 ${state} ≠ running"; exit 1; }
  host_tcp_ok || { fail "宿主 ${HOST}:${PORT} 不可达"; exit 1; }
  [[ "$(in_redis ping)" == "PONG" ]] || { fail "容器内 redis-cli PING 未返回 PONG"; exit 1; }
  pass "预检通过（容器 running / 宿主端口可达 / PING=PONG）"
}

# 恢复验证：PING + SET/GET 往返 + 健康检查 healthy
verify_recovery() {
  local scenario="$1"
  step "等待容器 health=healthy"
  wait_healthy || { fail "${scenario}: 60s 内未恢复 healthy"; return; }
  pass "${scenario}: 容器 health=healthy"

  step "宿主端口探测恢复"
  if host_tcp_ok; then
    pass "${scenario}: 宿主 ${HOST}:${PORT} 重新可达"
  else
    fail "${scenario}: 宿主 ${HOST}:${PORT} 仍不可达"
  fi

  step "PING 恢复"
  if [[ "$(in_redis ping)" == "PONG" ]]; then
    pass "${scenario}: PING → PONG"
  else
    fail "${scenario}: PING 未恢复"
  fi

  step "写入/读取往返（恢复后新连接可用性）"
  if [[ "$(in_redis set "${CANARY_KEY}:recover" "$CANARY_VALUE")" == "OK" ]] \
    && [[ "$(in_redis get "${CANARY_KEY}:recover")" == "$CANARY_VALUE" ]]; then
    pass "${scenario}: SET/GET 往返成功"
  else
    fail "${scenario}: SET/GET 往返失败"
  fi
}

# 场景 1：容器暂停 → 恢复（SIGSTOP/SIGCONT；进程冻结，TCP 连接悬挂）
scenario_pause() {
  log "=== 场景 1/3：容器暂停 → 恢复（docker pause/unpause）==="
  step "注入：docker pause"
  docker pause "$CONTAINER" >/dev/null || { fail "docker pause 失败"; return; }
  step "故障期探测（进程冻结，PING 无响应；降级行为可观测）"
  if host_redis_down; then
    pass "故障注入生效：宿主 ${HOST}:${PORT} PING 无响应（应用侧应观测到缓存操作超时/回源 DAO，不得 panic 或阻塞工作线程）"
  else
    fail "PING 在 pause 期间仍有响应，故障未生效"
  fi
  step "解除：docker unpause"
  docker unpause "$CONTAINER" >/dev/null || { fail "docker unpause 失败"; return; }
  verify_recovery "pause"
}

# 场景 2：网络断开 → 重连（容器与 compose 网络解绑；端口映射失效）
scenario_disconnect() {
  log "=== 场景 2/3：网络断开 → 重连（docker network disconnect/connect）==="
  local network
  network="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER" | awk '{print $1}')"
  [[ -n "$network" ]] || { fail "无法定位容器网络"; return; }
  step "注入：从网络 ${network} 解绑"
  docker network disconnect "$network" "$CONTAINER" || { fail "network disconnect 失败"; return; }
  step "故障期探测（宿主 PING 无响应；容器内回环仍存活）"
  local loopback
  loopback="$(in_redis ping 2>/dev/null || true)"
  if host_redis_down && [[ "$loopback" == "PONG" ]]; then
    pass "故障注入生效：宿主侧 PING 无响应（代理可连但后端隔离），容器内 Redis 自身存活（网络层隔离而非进程故障）"
  else
    fail "故障注入未达预期（宿主仍可用或容器内已失活）"
  fi
  step "解除：重新接入网络 ${network}"
  docker network connect "$network" "$CONTAINER" || { fail "network connect 失败"; return; }
  verify_recovery "disconnect"
}

# 场景 3：强制重启（容器进程重建；/data 卷持久化保留）
scenario_restart() {
  log "=== 场景 3/3：强制重启（docker restart）==="
  step "预置金丝雀值（验证 /data 卷持久化）"
  in_redis set "$CANARY_KEY" "$CANARY_VALUE" >/dev/null || { fail "金丝雀写入失败"; return; }
  step "注入：docker restart（含短暂 stop 窗口，宿主连接被重置）"
  docker restart "$CONTAINER" >/dev/null || { fail "docker restart 失败"; return; }
  step "故障期探测（重启窗口内宿主 PING 应无响应）"
  if host_redis_down; then
    pass "故障注入生效：重启窗口内宿主不可用"
  else
    fail "重启窗口内宿主仍可用（窗口过短或注入未生效）"
  fi
  verify_recovery "restart"
  step "金丝雀持久化断言（restart 不丢 /data 卷数据）"
  if [[ "$(in_redis get "$CANARY_KEY")" == "$CANARY_VALUE" ]]; then
    pass "金丝雀值跨重启保留（volume 持久化生效）"
  else
    fail "金丝雀值丢失——/data 卷未按预期持久化"
  fi
}

# 场景 4：Sentinel 主从故障切换（chaos profile：master/replica/sentinel）。
# 演练拓扑为单 Sentinel + quorum 1（提速）；生产建议 ≥3 Sentinel + quorum 2。
scenario_sentinel() {
  log "=== 场景 4/4：Redis Sentinel 主从故障切换（docker compose --profile chaos）==="
  step "拉起演练拓扑（master + replica + sentinel）"
  docker compose -f docker-compose.e2e.yml --profile chaos up -d \
    redis-chaos-master redis-chaos-replica redis-chaos-sentinel >/dev/null || {
    fail "chaos profile 拉起失败"
    return
  }

  local sentinel_cli="docker exec garrison-chaos-sentinel redis-cli -p 26379"
  local master_cli="docker exec garrison-chaos-master redis-cli"
  local replica_cli="docker exec garrison-chaos-replica redis-cli"

  step "等待 Sentinel 进入监控（≤60s）"
  # resolve-hostnames 开启时 get-master-addr 返回裸主机名行（非旧版引号格式），
  # 以首行非空为准
  local deadline=$((SECONDS + 60))
  until [[ -n "$($sentinel_cli sentinel get-master-addr-by-name mymaster 2>/dev/null | head -1)" ]]; do
    (( SECONDS < deadline )) || { fail "Sentinel 60s 内未进入监控"; return; }
    sleep 1
  done
  pass "Sentinel 已监控 mymaster"

  step "预置金丝雀值（写入主库，验证复制 + 提升后可读）"
  if [[ "$($master_cli set "${CANARY_KEY}:sentinel" "$CANARY_VALUE")" == "OK" ]]; then
    pass "金丝雀写入主库成功"
  else
    fail "金丝雀写入主库失败"
    return
  fi

  step "等待金丝雀复制到副本（≤10s，消除异步复制竞态）"
  deadline=$((SECONDS + 10))
  until [[ "$($replica_cli get "${CANARY_KEY}:sentinel")" == "$CANARY_VALUE" ]]; do
    (( SECONDS < deadline )) || { fail "金丝雀 10s 内未复制到副本"; return; }
    sleep 1
  done
  pass "金丝雀已在副本可见（复制确认）"

  step "注入：docker pause 主库（进程冻结 → Sentinel sdown → odown → failover）"
  docker pause garrison-chaos-master >/dev/null || { fail "pause 主库失败"; return; }

  step "等待副本提升为主（≤120s，含 sdown→选举→提升全链路）"
  deadline=$((SECONDS + 120))
  local promoted=0
  while (( SECONDS < deadline )); do
    if [[ "$($replica_cli role 2>/dev/null | head -1)" == "master" ]]; then
      promoted=1
      break
    fi
    sleep 1
  done
  if (( promoted == 1 )); then
    pass "副本已提升为主（Sentinel 自动故障切换生效）"
  else
    fail "120s 内副本未提升——检查 Sentinel 状态"
    docker unpause garrison-chaos-master >/dev/null 2>&1
    return
  fi

  step "提升后可写 + 金丝雀可读（复制数据不丢）"
  if [[ "$($replica_cli set "${CANARY_KEY}:sentinel-promoted" ok)" == "OK" ]] \
    && [[ "$($replica_cli get "${CANARY_KEY}:sentinel")" == "$CANARY_VALUE" ]]; then
    pass "提升主库读写正常，切换前写入的金丝雀已随复制同步"
  else
    fail "提升主库读写或金丝雀读取异常"
  fi

  step "恢复：unpause 旧主库（Sentinel 将其降级为副本重新入列）"
  docker unpause garrison-chaos-master >/dev/null || { fail "unpause 旧主库失败"; return; }
  deadline=$((SECONDS + 60))
  local rejoined=0
  while (( SECONDS < deadline )); do
    if [[ "$($master_cli role 2>/dev/null | head -1)" == "slave" ]]; then
      rejoined=1
      break
    fi
    sleep 1
  done
  if (( rejoined == 1 )); then
    pass "旧主库已降级为副本重新入列（拓扑收敛）"
  else
    fail "旧主库 60s 内未降级为副本"
  fi

  step "清理演练拓扑（精确移除，不影响主 e2e Redis）"
  # 不用 `compose --profile chaos down`：它会下线整个 compose 项目（含主 Redis）
  docker rm -f garrison-chaos-master garrison-chaos-replica garrison-chaos-sentinel >/dev/null 2>&1 || true
  pass "chaos 拓扑已下线"
}

cleanup() {
  # 中断兜底：确保容器不被遗留为 paused / 孤离网络状态
  docker inspect -f '{{.State.Paused}}' "$CONTAINER" 2>/dev/null | grep -q true \
    && docker unpause "$CONTAINER" >/dev/null 2>&1
  # Sentinel 演练容器中断兜底
  docker inspect -f '{{.State.Paused}}' garrison-chaos-master 2>/dev/null | grep -q true \
    && docker unpause garrison-chaos-master >/dev/null 2>&1
}
trap cleanup EXIT

main() {
  preflight
  local scenario="${1:-all}"
  case "$scenario" in
    pause)      scenario_pause ;;
    disconnect) scenario_disconnect ;;
    restart)    scenario_restart ;;
    sentinel)   scenario_sentinel ;;
    all)
      scenario_pause
      scenario_disconnect
      scenario_restart
      scenario_sentinel
      ;;
    *)
      log "未知场景: ${scenario}（可用: pause / disconnect / restart / sentinel / all）"
      exit 1
      ;;
  esac

  log ""
  if (( FAILED == 0 )); then
    log "=== 演练完成：全部场景 [PASS] ==="
    log "判读标准见 docs/RELIABILITY.md（降级行为观测 / 恢复验证 / 金丝雀断言）"
  else
    log "=== 演练完成：存在 [FAIL] 场景，退出码 1 ==="
    exit 1
  fi
}

main "${1:-all}"
