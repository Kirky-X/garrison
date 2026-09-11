#!/bin/bash
# Copyright (c) 2026 Kirky.X. All rights reserved.
# See LICENSE for full license text.

# Garrison E2E 特性组合测试套件（一键全量质量门禁）。
#
# 按 CI/CD Pipeline Design 方法论组织为 8 个阶段门禁，fail-fast 粒度为
# 「阶段内短路、阶段间继续收集」——任一阶段失败都记录并在结尾汇总，
# 但依赖外部服务/编译产物的阶段在前提缺失时显式跳过（[SKIP] 语义与
# tests/acceptance/environment.rs 一致）。
#
# 阶段：
#   S0 环境自举    docker compose 拉起 Redis(16379)/PostgreSQL(15432)/MySQL(13306)
#                  （Keycloak 18090 可选 --with-keycloak），健康探活后注入
#                  GARRISON_TEST_* 地址覆盖环境变量
#   S1 静态门禁    rustfmt --check / clippy(default) / clippy(full) / cargo-deny
#   S2 单元测试    cargo test --lib（default 与 full 两种特性面）
#   S3 验收/集成   cargo test --features full --tests --no-fail-fast
#                  （tests/acceptance 19 域：正常/异常/组合场景，
#                   Redis/Postgres/MySQL(testcontainers) 真实服务路径）
#   S4 示例套件    cargo test -p garrison-examples --all-features
#   S5 特性矩阵    聚合特性(default/development/production/full) + web×db 网格
#                  (axum/actix/warp × sqlite/postgres/mysql) + 定向两两组合的
#                  check 与测试编译；--full-matrix 追加 cargo-hack each-feature 全量
#   S6 性能基准    criterion --quick，保存/对比 e2e 基线，回归即失败
#   S7 HTTP E2E    auth_server_serve + scripts/e2e_run.sh（外部 18080/内部 18081）
#   S8 清理报告    docker compose down -v --remove-orphans + Markdown 汇总报告
#
# 用法：
#   bash scripts/e2e_matrix.sh                  # 默认快速矩阵
#   bash scripts/e2e_matrix.sh --full-matrix    # 追加 each-feature 全量扫描（数小时）
#   bash scripts/e2e_matrix.sh --skip-bench     # 跳过性能基准
#   bash scripts/e2e_matrix.sh --skip-e2e-http  # 跳过 HTTP E2E（快速迭代）
#   bash scripts/e2e_matrix.sh --keep-env       # 结束后保留 compose 环境（调试）
#   bash scripts/e2e_matrix.sh --with-keycloak  # 额外拉起 Keycloak（手动 OIDC 联调）
#
# 输出：
#   logs/e2e_matrix/<stage>.log   各阶段完整日志
#   logs/e2e_matrix_report.md     汇总报告（阶段结果/基准回归/组合矩阵结果）
#
# 清理保证：compose 项目名固定 garrison-e2e，down -v 只清理本套件创建的
# 容器与卷，不触碰宿主机其他容器（如开发机常驻的 sinnan-*/confers-*）。
# 退出码：0 = 全部阶段通过；1 = 存在失败阶段（见报告）。

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# ---------- 参数解析 ----------
FULL_MATRIX=false
KEEP_ENV=false
SKIP_BENCH=false
SKIP_E2E_HTTP=false
WITH_KEYCLOAK=false
while [ $# -gt 0 ]; do
    case "$1" in
        --full-matrix) FULL_MATRIX=true ;;
        --keep-env) KEEP_ENV=true ;;
        --skip-bench) SKIP_BENCH=true ;;
        --skip-e2e-http) SKIP_E2E_HTTP=true ;;
        --with-keycloak) WITH_KEYCLOAK=true ;;
        -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "未知参数: $1（--help 查看用法）" >&2; exit 2 ;;
    esac
    shift
done

# ---------- 全局环境（与 CI 对齐：零告警硬门禁） ----------
export RUSTFLAGS="-D warnings"
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1
# CI Linux 同款：规避 sqlite 文件库 SQLITE_READONLY 偶发（见 ci.yml test job）
export GARRISON_TEST_SQLITE_MEMORY=1

COMPOSE="docker compose -f docker-compose.e2e.yml"
LOG_DIR="${REPO_ROOT}/logs/e2e_matrix"
mkdir -p "${LOG_DIR}"

FAILED_STAGES=()
SKIPPED_STAGES=()
PASSED_STAGES=()

log_stage() { echo ""; echo "=================================================================="; echo "=== [STAGE $1] $2"; echo "=================================================================="; }

record_pass() { PASSED_STAGES+=("$1"); echo ">>> [$1] PASS"; }
record_fail() { FAILED_STAGES+=("$1"); echo ">>> [$1] FAIL（日志: ${LOG_DIR}/$1.log）"; }
record_skip() { SKIPPED_STAGES+=("$1"); echo ">>> [$1] SKIP — $2"; }

run_stage() {
    local id="$1" name="$2"; shift 2
    log_stage "${id}" "${name}"
    if "$@" >"${LOG_DIR}/${id}.log" 2>&1; then
        record_pass "${id}"
        return 0
    fi
    record_fail "${id}"
    # 阶段失败时把日志尾部直接打到终端，省一次翻文件
    echo "--- ${id} 日志尾部（最后 40 行） ---"
    tail -n 40 "${LOG_DIR}/${id}.log"
    return 1
}

# ==========================================================================
# S0 环境自举
# ==========================================================================
log_stage "S0" "环境自举（docker compose 中间件）"
ENV_READY=false
PROFILE_ARGS=()
if [ "${WITH_KEYCLOAK}" = "true" ]; then
    PROFILE_ARGS=(--profile keycloak)
fi
if ! docker info > /dev/null 2>&1; then
    record_skip "S0" "docker daemon 不可达，服务依赖阶段将按探测结果 [SKIP]"
else
    if ${COMPOSE} up -d "${PROFILE_ARGS[@]}" --wait >"${LOG_DIR}/S0.log" 2>&1; then
        # 探活（2s 超时 ×2 轮重试，compose --wait 已含健康检查，此处为双保险）
        probe() { (echo > "/dev/tcp/$1/$2") > /dev/null 2>&1; }
        REDIS_OK=false; PG_OK=false
        for i in 1 2; do
            probe 127.0.0.1 16379 && REDIS_OK=true
            probe 127.0.0.1 15432 && PG_OK=true
            ${REDIS_OK} && ${PG_OK} && break
            sleep 2
        done
        if ${REDIS_OK} && ${PG_OK}; then
            # 地址覆盖：验收测试经 GARRISON_TEST_* 读取（默认值不变，向后兼容）
            export GARRISON_TEST_REDIS_ADDR="127.0.0.1:16379"
            export GARRISON_TEST_REDIS_URL="redis://127.0.0.1:16379"
            export GARRISON_TEST_POSTGRES_ADDR="127.0.0.1:15432"
            export GARRISON_TEST_POSTGRES_URL="postgres://garrison:garrison@localhost:15432/garrison_test"
            ENV_READY=true
            echo "Redis(16379) + PostgreSQL(15432) + MySQL(13306) 就绪$( [ "${WITH_KEYCLOAK}" = "true" ] && echo ' + Keycloak(18090)' )"
            record_pass "S0"
        else
            echo "Redis 可达=${REDIS_OK} Postgres 可达=${PG_OK}" | tee -a "${LOG_DIR}/S0.log"
            record_fail "S0"
        fi
    else
        echo "compose up --wait 失败：" >&2
        tail -n 20 "${LOG_DIR}/S0.log" >&2
        record_fail "S0"
    fi
fi

if [ "${ENV_READY}" != "true" ]; then
    record_skip "S3" "外部服务未就绪（S0 未通过），验收/集成测试中的服务真实路径将退化为 [SKIP]"
fi

# ==========================================================================
# S1 静态门禁
# ==========================================================================
S1_OK=true
run_stage "S1a" "rustfmt --check" bash -c 'cargo fmt --all -- --check' || S1_OK=false
run_stage "S1b" "clippy (default features)" \
    bash -c 'cargo clippy --no-default-features --features "default" --locked -- -D warnings' || S1_OK=false
run_stage "S1c" "clippy (full features)" \
    bash -c 'cargo clippy --features "full" --locked -- -D warnings' || S1_OK=false
run_stage "S1d" "cargo-deny (advisories/bans/licenses/sources, all-features)" \
    bash -c 'cargo deny --all-features --locked check' || S1_OK=false
if ${S1_OK}; then record_pass "S1"; else record_fail "S1"; fi

# ==========================================================================
# S2 单元测试（lib，default 与 full 两极）
# ==========================================================================
S2_OK=true
run_stage "S2a" "lib tests (default = backend-embedded)" \
    bash -c 'cargo test --no-default-features --features "default" --lib --locked' || S2_OK=false
run_stage "S2b" "lib tests (full features)" \
    bash -c 'cargo test --features "full" --lib --locked' || S2_OK=false
if ${S2_OK}; then record_pass "S2"; else record_fail "S2"; fi

# ==========================================================================
# S3 验收/集成测试（tests/ 全部 target，full 特性面）
# ==========================================================================
if [ "${ENV_READY}" = "true" ]; then
    run_stage "S3" "integration + acceptance tests (full, real Redis/Postgres/MySQL)" \
        bash -c 'cargo test --features "full" --tests --no-fail-fast --locked'
    # db 后端专用验收：dbnexus 禁止 embedded(sqlite)×server-side(postgres/mysql)
    # 共存 → full 面下 ACC-ENV-005..008 被 cfg 剥离，需按单 db 特性面单独执行
    run_stage "S3pg" "acceptance_db_postgres (real PostgreSQL via compose :15432)" \
        bash -c 'GARRISON_TEST_POSTGRES_ADDR=127.0.0.1:15432 GARRISON_TEST_POSTGRES_URL=postgres://garrison:garrison@localhost:15432/garrison_test cargo test --test acceptance_db_postgres --no-default-features --features "db-postgres" --locked -- --test-threads=1'
    run_stage "S3my" "acceptance_db_mysql (MySQL via testcontainers)" \
        bash -c 'cargo test --test acceptance_db_mysql --no-default-features --features "db-mysql" --locked -- --test-threads=1'
fi

# ==========================================================================
# S4 示例套件（独立 workspace member，CI 盲区补齐）
# ==========================================================================
run_stage "S4" "examples tests (all features)" \
    bash -c 'cargo test -p garrison-examples --all-features --locked'

# ==========================================================================
# S5 特性组合矩阵
# ==========================================================================
# 组合语义说明：
#   - dbnexus 硬约束「embedded(sqlite) 与 server-side(postgres/mysql) 互斥」，
#     故 web×db 网格每次只挂一个 db 后端（多 web 框架共存合法）；
#   - 每个组合同时验证「库编译」与「测试代码编译」（--lib --no-run），
#     后者是 2026-09 实录的测试代码 feature 门控漂移防线（ci.yml guard job）。
MATRIX_OK=true

matrix_combo() {
    local label="$1" features="$2"
    local feat_args=()
    [ -n "${features}" ] && feat_args=(--features "${features}")
    if cargo check --no-default-features "${feat_args[@]}" --locked \
        >>"${LOG_DIR}/S5.log" 2>&1 \
        && cargo test --lib --no-run --no-default-features "${feat_args[@]}" --locked \
        >>"${LOG_DIR}/S5.log" 2>&1; then
        echo "  ✅ ${label} [${features}]"
    else
        echo "  ❌ ${label} [${features}]（详情: ${LOG_DIR}/S5.log）"
        MATRIX_OK=false
    fi
}

echo "=== [STAGE S5] 特性组合矩阵（编译级） ==="
{
    echo "# S5 特性组合矩阵 — $(date -Is)"
    echo "## 聚合特性"
    for agg in default development production full; do
        matrix_combo "聚合-${agg}" "${agg}"
    done

    echo "## web × db 网格（每组合单 db 后端，dbnexus embedded/server-side 互斥约束）"
    for web in web-axum web-actix web-warp; do
        for db in db-sqlite db-postgres db-mysql; do
            matrix_combo "${web}×${db}" "${web},${db}"
        done
    done
    matrix_combo "三web×sqlite" "web-axum,web-actix,web-warp,db-sqlite"
    matrix_combo "三web×postgres" "web-axum,web-actix,web-warp,db-postgres"
    matrix_combo "三web×mysql" "web-axum,web-actix,web-warp,db-mysql"

    echo "## 定向两两组合（历史事故面 + ci.yml test-compile-guard 清单）"
    matrix_combo "db-mysql+embedded-migrations" "db-mysql,embedded-migrations"
    matrix_combo "db-sqlite+protocol-apikey" "db-sqlite,protocol-apikey"
    matrix_combo "db-postgres+three-tier-cache" "db-postgres,three-tier-cache"
    matrix_combo "protocol-jwt+secure-ct-eq" "protocol-jwt,secure-ct-eq"
    matrix_combo "protocol-saml+protocol-oidc" "protocol-saml,protocol-oidc"
    matrix_combo "web-warp+annotation-macros" "web-warp,annotation-macros"
    matrix_combo "web-actix+web-security" "web-actix,web-security"
    matrix_combo "auth-server+backend-remote" "auth-server,backend-remote"
    matrix_combo "oauth2-server+cache-redis" "oauth2-server,cache-redis"
    matrix_combo "tenant-isolation+firewall-bruteforce" "tenant-isolation,firewall-bruteforce"
    matrix_combo "db-web-policy-listener" "db-sqlite,web-axum,account-policy,listener"
    matrix_combo "email-credential-authflow" "email-verification,email-verification-smtp,account-credential,account-authflow"
    matrix_combo "full+testing（验收 target 实际特性面）" "full,testing"
    matrix_combo "minimal（零特性）" ""
} 2>&1 | tee "${LOG_DIR}/S5.progress"

if [ "${FULL_MATRIX}" = "true" ]; then
    echo "=== [STAGE S5x] each-feature 全量扫描（cargo-hack，耗时数小时） ==="
    # 注意：① 不可加 --locked——--no-dev-deps 会临时改写 manifest（剥离 dev-deps），
    # lockfile 随之需要更新，--locked 必然拒绝（与 CI feature-matrix.yml 一致）；
    # ② 必须排除 --all-features 基线——dbnexus 禁止 embedded×server-side 共存，
    # all-features 同时启用 db-sqlite+db-postgres 必然 compile_error（预期约束）。
    if run_stage "S5x" "cargo hack check --each-feature" \
        bash -c 'cargo hack check --each-feature --no-dev-deps --keep-going --exclude-all-features'; then
        # 单 feature 测试编译兜底（排除聚合特性，与 feature-matrix.yml 同清单逻辑；
        # 此处未改写 manifest，--locked 合法）
        FEATURES=$(cargo metadata --no-deps --format-version 1 --locked \
            | python3 -c "import json,sys; md=json.load(sys.stdin); [print(f) for p in md['packages'] if p['name']=='garrison' for f in sorted(p['features']) if f not in ('default','full','production','development')]")
        LOOP_OK=true
        : > "${LOG_DIR}/S5y.log"
        for f in ${FEATURES}; do
            if ! cargo test --lib --no-run --no-default-features --features "${f}" --locked \
                >>"${LOG_DIR}/S5y.log" 2>&1; then
                echo "❌ feature '${f}' 测试编译失败（详情: ${LOG_DIR}/S5y.log）"
                LOOP_OK=false
            fi
        done
        if ${LOOP_OK}; then record_pass "S5y"; else record_fail "S5y"; fi
    else
        record_fail "S5x"
    fi
else
    record_skip "S5x" "未指定 --full-matrix（each-feature 全量扫描跳过；每周 CI feature-matrix 工作流兜底）"
fi
if ${MATRIX_OK}; then record_pass "S5"; else record_fail "S5"; fi

# ==========================================================================
# S6 性能基准
# ==========================================================================
if [ "${SKIP_BENCH}" = "true" ]; then
    record_skip "S6" "--skip-bench"
else
    log_stage "S6" "性能基准（criterion --quick，基线 e2e）"
    # --bench 限定 criterion 目标：裸 `cargo bench` 会连带以 bench profile 跑
    # lib unittest（不认识 criterion 参数 → "Unrecognized option: 'quick'"）
    # 首跑保存基线；后续跑 criterion 自动输出相对基线的 change，
    # 出现 "Regressed" 判定即失败（噪声阈值由 criterion 统计置信区间决定）
    if cargo bench --bench garrison_benchmark --features full --locked -- \
        --quick --save-baseline e2e >"${LOG_DIR}/S6.log" 2>&1; then
        if grep -qi "regressed" "${LOG_DIR}/S6.log"; then
            grep -iB2 -A2 "regressed" "${LOG_DIR}/S6.log" | head -40
            record_fail "S6"
        else
            grep -E "^(login_flow|token_verify|permission_check|oxcache|change|Benchmarking .*: Collecting)" "${LOG_DIR}/S6.log" \
                | tail -20 || true
            record_pass "S6"
        fi
    else
        tail -n 40 "${LOG_DIR}/S6.log"
        record_fail "S6"
    fi
fi

# ==========================================================================
# S7 HTTP E2E（examples auth_server_serve + e2e_run.sh）
# ==========================================================================
if [ "${SKIP_E2E_HTTP}" = "true" ]; then
    record_skip "S7" "--skip-e2e-http"
else
    log_stage "S7" "HTTP E2E（auth_server_serve + e2e_run.sh，外部 18080 / 内部 18081）"
    # 8080/8081 在开发机常被驻留服务占用，套件固定用高位端口
    export GARRISON_EXTERNAL_PORT="${GARRISON_EXTERNAL_PORT:-18080}"
    export GARRISON_INTERNAL_PORT="${GARRISON_INTERNAL_PORT:-18081}"
    export GARRISON_RATE_LIMIT="${GARRISON_RATE_LIMIT:-100000}"
    export EXAMPLE_INTERNAL_API_KEY="${EXAMPLE_INTERNAL_API_KEY:-$(openssl rand -hex 16)}"
    if bash scripts/e2e_run.sh >"${LOG_DIR}/S7.log" 2>&1; then
        record_pass "S7"
    else
        tail -n 60 "${LOG_DIR}/S7.log"
        record_fail "S7"
    fi
fi

# ==========================================================================
# S8 清理 + 报告
# ==========================================================================
if [ "${KEEP_ENV}" = "true" ]; then
    record_skip "S8-cleanup" "--keep-env：保留 garrison-e2e compose 环境（手动 down：${COMPOSE} down -v --remove-orphans）"
elif command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
    log_stage "S8" "清理 compose 环境（容器 + 卷）"
    if ${COMPOSE} down -v --remove-orphans --timeout 10 >"${LOG_DIR}/S8-cleanup.log" 2>&1; then
        echo "garrison-e2e 容器与卷已清理"
        record_pass "S8-cleanup"
    else
        tail -n 10 "${LOG_DIR}/S8-cleanup.log"
        record_fail "S8-cleanup"
    fi
else
    record_skip "S8-cleanup" "docker 不可达，跳过清理"
fi

# ---------- 汇总报告 ----------
REPORT="${REPO_ROOT}/logs/e2e_matrix_report.md"
{
    echo "# Garrison E2E 特性组合测试报告"
    echo ""
    echo "- 时间：$(date -Is)"
    echo "- 工具链：$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"
    echo "- 工作树：$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'no git') $([ -z "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" ] && echo '(clean)' || echo '(dirty)')"
    echo "- 模式：$([ "${FULL_MATRIX}" = "true" ] && echo 'full-matrix' || echo 'quick') bench=$([ "${SKIP_BENCH}" = "true" ] && echo off || echo on) e2e-http=$([ "${SKIP_E2E_HTTP}" = "true" ] && echo off || echo on)"
    echo ""
    echo "## 阶段结果"
    echo ""
    echo "| 阶段 | 结果 |"
    echo "|------|------|"
    for s in "${PASSED_STAGES[@]:-}"; do [ -n "${s}" ] && echo "| ${s} | ✅ PASS |"; done
    for s in "${SKIPPED_STAGES[@]:-}"; do [ -n "${s}" ] && echo "| ${s} | ⏭️ SKIP |"; done
    for s in "${FAILED_STAGES[@]:-}"; do [ -n "${s}" ] && echo "| ${s} | ❌ FAIL |"; done
    echo ""
    echo "各阶段完整日志：logs/e2e_matrix/<stage>.log"
} > "${REPORT}"

echo ""
echo "=================================================================="
echo "=== E2E 套件完成"
echo "=== PASS: ${#PASSED_STAGES[@]}  SKIP: ${#SKIPPED_STAGES[@]}  FAIL: ${#FAILED_STAGES[@]}"
echo "=== 报告: ${REPORT}"
echo "=================================================================="

if [ "${#FAILED_STAGES[@]}" -gt 0 ]; then
    echo "失败阶段: ${FAILED_STAGES[*]}"
    exit 1
fi
exit 0
