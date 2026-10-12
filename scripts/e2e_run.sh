#!/bin/bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# 环境变量 fail-closed：EXAMPLE_INTERNAL_API_KEY 必须显式设置，不硬编码默认 key（避免生产误用 e2e 测试 key）。
if [ -z "${EXAMPLE_INTERNAL_API_KEY:-}" ]; then
    echo "FATAL: EXAMPLE_INTERNAL_API_KEY 未设置。请显式提供 e2e 测试用 API Key。" >&2
    echo "       例：EXAMPLE_INTERNAL_API_KEY=\$(openssl rand -hex 16) bash scripts/e2e_run.sh" >&2
    exit 1
fi
export EXAMPLE_INTERNAL_API_KEY
export GARRISON_EXTERNAL_PORT="${GARRISON_EXTERNAL_PORT:-8080}"
export GARRISON_INTERNAL_PORT="${GARRISON_INTERNAL_PORT:-8081}"
export GARRISON_RATE_LIMIT="${GARRISON_RATE_LIMIT:-100000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# 确保 logs/ 目录存在（避免首次运行时 health check 日志写入失败）
mkdir -p logs

# 后台启动 auth_server_serve（stderr 重定向到日志文件，health check 失败时 dump）
echo "=== [1/6] 启动 auth_server_serve（background） ==="
STDERR_LOG="${REPO_ROOT}/logs/auth_server_serve.stderr.log"
cargo run -p garrison-examples --bin auth_server_serve --features full 2>"${STDERR_LOG}" &
SERVER_PID=$!

# trap 退出时杀子进程（防止残留僵尸进程）
cleanup() {
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "=== cleanup: 终止 auth_server_serve (PID=${SERVER_PID}) ==="
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# health check 重试 30 次（每次 1s）；用 GET /api/v1/auth/health 替代 POST /login，避免副作用
echo "=== [2/6] 等待 auth_server_serve 就绪（health check, 最多 30s） ==="
INTERNAL_URL="http://127.0.0.1:${GARRISON_INTERNAL_PORT}"
HEALTH_OK=false
for i in $(seq 1 30); do
    if curl --fail --silent --max-time 1 "${INTERNAL_URL}/api/v1/auth/health" \
        -H "X-Tenant-Id: 0" \
        -H "x-api-key: ${EXAMPLE_INTERNAL_API_KEY}" \
        >/dev/null 2>&1; then
        echo "  health check 通过 (attempt=${i})"
        HEALTH_OK=true
        break
    fi
    echo "  health check 失败 (attempt=${i}/30)，1s 后重试..."
    sleep 1
done

if [ "${HEALTH_OK}" != "true" ]; then
    echo "FATAL: auth_server_serve 30s 内未就绪，退出" >&2
    echo "  server stderr 日志（最后 50 行）:" >&2
    tail -n 50 "${STDERR_LOG}" >&2 2>/dev/null || echo "  (stderr 日志不可读: ${STDERR_LOG})" >&2
    echo "  完整日志路径: ${STDERR_LOG}" >&2
    exit 1
fi

# 依次执行测试套件（tests/acceptance 现行 target；testing feature 门控 garrison/testing 测试辅助设施；套件随机端口自 spawn，并行安全）
echo "=== [3/5] 全量验收套件（含 pentest 攻击面 security:: 域） ==="
cargo test --test acceptance --features "full testing"

echo "=== [4/5] 性能基线（#[ignore] perf_*，追加 logs/perf.jsonl） ==="
cargo test --test acceptance --features "full testing" perf_ -- \
    --nocapture --test-threads=1 --ignored

# 聚合生成 Markdown 报告（缺失日志源在报告中显性标注「不存在」）
echo "=== [5/5] 生成 Markdown 综合报告 ==="
python3 scripts/e2e_analyze.py --log-dir logs

echo ""
echo "=== 全部完成 ==="
echo "  - 性能日志:      logs/perf.jsonl"
echo "  - 综合报告:      logs/e2e_final_report.md"
