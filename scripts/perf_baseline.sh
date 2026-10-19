#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 采集 garrison v1.0 性能基线（同机相对基线，不发布绝对耗时数字）。
#
# 用法：
#   bash scripts/perf_baseline.sh                 # 完整采样，基线名 v1.0-pre
#   BASELINE=my-base bash scripts/perf_baseline.sh
#   bash scripts/perf_baseline.sh --quick         # 快速采样（criterion --quick）
#
# 产物：
#   logs/perf-baseline.md     环境 + 命令 + criterion 输出
#   target/criterion/         criterion HTML/JSON 报告（不入库）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

BASELINE="${BASELINE:-v1.0-pre}"
OUT="${OUT:-logs/perf-baseline.md}"
QUICK=""
if [[ "${1:-}" == "--quick" ]]; then
  QUICK="--quick"
fi

mkdir -p logs

{
  echo "# Garrison 性能基线"
  echo
  echo "- 采集时间（UTC）：$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "- 基线名称：\`${BASELINE}\`"
  echo "- git：\`$(git rev-parse HEAD 2>/dev/null || echo unknown)\`"
  echo "- rustc：\`$(rustc -V 2>/dev/null | head -n1 || echo unknown)\`"
  echo "- cargo：\`$(cargo -V 2>/dev/null | head -n1 || echo unknown)\`"
  echo "- 采样模式：$([[ -n "${QUICK}" ]] && echo 'quick' || echo 'full')"
  echo "- 说明：本文只记录同机相对基线；不同机器/负载下绝对值不可横向比较。"
  echo
  echo "## 环境"
  echo
  echo '```text'
  uname -a 2>/dev/null || true
  if [[ -r /proc/cpuinfo ]]; then
    grep -m1 'model name' /proc/cpuinfo || true
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  fi
  echo '```'
  echo
  echo "## 运行命令"
  echo
  echo '```bash'
  echo "cargo bench --features full --bench garrison_benchmark -- --save-baseline ${BASELINE} ${QUICK}"
  echo '```'
  echo
  echo "## criterion 输出"
  echo
  echo '```text'
} > "${OUT}"

set +e
if [[ -n "${QUICK}" ]]; then
  cargo bench --features full --bench garrison_benchmark -- --save-baseline "${BASELINE}" "${QUICK}" 2>&1 | tee -a "${OUT}"
else
  cargo bench --features full --bench garrison_benchmark -- --save-baseline "${BASELINE}" 2>&1 | tee -a "${OUT}"
fi
BENCH_STATUS=${PIPESTATUS[0]}
set -e

{
  echo '```'
  echo
  echo "- criterion HTML：\`target/criterion/\`（不入库）"
  echo "- 退出码：${BENCH_STATUS}"
} >> "${OUT}"

echo "==> 完成：${OUT}"
exit "${BENCH_STATUS}"
