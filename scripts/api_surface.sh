#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 生成 garrison 公共 API 面基线（v1.0 API 冻结门禁的启动材料）。
#
# 用法：
#   bash scripts/api_surface.sh                    # 生成 logs/api-surface.txt
#   bash scripts/api_surface.sh --diff <baseline>  # 额外打印与基线的差异
#
# 依赖：nightly 工具链（rustdoc JSON）、python3。
# 说明：report-only；不因差异返回非零退出码。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

TOOLCHAIN="${TOOLCHAIN:-nightly}"
OUT="${OUT:-logs/api-surface.txt}"
JSON="${RUSTDOC_JSON:-target/doc/garrison.json}"

DIFF_BASELINE=""
if [[ "${1:-}" == "--diff" && -n "${2:-}" ]]; then
  DIFF_BASELINE="${2}"
fi

mkdir -p logs

echo "==> cargo +${TOOLCHAIN} rustdoc --features full --lib (rustdoc JSON)"
cargo "+${TOOLCHAIN}" rustdoc --features full --lib -- -Zunstable-options --output-format json

if [[ ! -f "${JSON}" ]]; then
  echo "ERROR: rustdoc JSON 未生成: ${JSON}" >&2
  exit 1
fi

echo "==> 解析公共面 -> ${OUT}"
if [[ -n "${DIFF_BASELINE}" ]]; then
  python3 scripts/api_surface.py "${JSON}" --diff "${DIFF_BASELINE}" > "${OUT}"
else
  python3 scripts/api_surface.py "${JSON}" > "${OUT}"
fi

echo "==> 完成：${OUT}（共 $(grep -vc '^#' "${OUT}" || true) 项）"
