#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 生成 garrison 公共 API 面基线（v1.0 API 冻结门禁的仓库侧产物）。
#
# 用法：
#   bash scripts/api_surface.sh                    # 生成 logs/api-surface.txt
#   bash scripts/api_surface.sh --diff <baseline>  # 额外打印与基线的差异
#   bash scripts/api_surface.sh --help             # 输出用法并退出 0（不触发 rustdoc 构建）
#
# 环境变量：
#   TOOLCHAIN              rustdoc 工具链（默认 nightly）
#   OUT                    公共面清单输出路径（默认 logs/api-surface.txt）
#   RUSTDOC_JSON           rustdoc JSON 路径（默认 target/doc/garrison.json）
#   API_SURFACE_DIFF_JSON  结构化差异 JSON 输出路径（默认 logs/api-surface-diff.json）
#
# 依赖：nightly 工具链（rustdoc JSON）、python3。
# 说明：report-only；不因差异返回非零退出码。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

usage() {
  cat <<'USAGE'
用法：bash scripts/api_surface.sh [选项]

选项：
  --help                 输出本用法并退出 0（不触发 rustdoc 构建）
  --diff <baseline>      与基线文件比较，额外打印新增/移除/修改项
  --diff-json <path>     结构化差异 JSON 输出路径
                         （默认 logs/api-surface-diff.json，可用环境变量
                          API_SURFACE_DIFF_JSON 覆盖）

环境变量：
  TOOLCHAIN              rustdoc 工具链（默认 nightly）
  OUT                    公共面清单输出路径（默认 logs/api-surface.txt）
  RUSTDOC_JSON           rustdoc JSON 路径（默认 target/doc/garrison.json）
  API_SURFACE_DIFF_JSON  结构化差异 JSON 输出路径（默认 logs/api-surface-diff.json）

产物：
  logs/api-surface.txt           公共面清单（kind + 路径 + 签名指纹）
  logs/api-surface-diff.json     结构化差异（仅 --diff 时生成）

退出码：0 = 完成（report-only，差异不阻断）；1 = rustdoc JSON 未生成；2 = 参数错误。
USAGE
}

TOOLCHAIN="${TOOLCHAIN:-nightly}"
OUT="${OUT:-logs/api-surface.txt}"
JSON="${RUSTDOC_JSON:-target/doc/garrison.json}"
DIFF_JSON="${API_SURFACE_DIFF_JSON:-logs/api-surface-diff.json}"

DIFF_BASELINE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --diff)
      [[ $# -ge 2 ]] || { echo "ERROR: --diff 缺少基线文件参数" >&2; exit 2; }
      DIFF_BASELINE="$2"
      shift 2
      ;;
    --diff-json)
      [[ $# -ge 2 ]] || { echo "ERROR: --diff-json 缺少输出路径参数" >&2; exit 2; }
      DIFF_JSON="$2"
      shift 2
      ;;
    *)
      echo "ERROR: 未知参数: $1（--help 查看用法）" >&2
      exit 2
      ;;
  esac
done

mkdir -p logs

echo "==> cargo +${TOOLCHAIN} rustdoc --features full --lib (rustdoc JSON)"
cargo "+${TOOLCHAIN}" rustdoc --features full --lib -- -Zunstable-options --output-format json

if [[ ! -f "${JSON}" ]]; then
  echo "ERROR: rustdoc JSON 未生成: ${JSON}" >&2
  exit 1
fi

echo "==> 解析公共面 -> ${OUT}"
if [[ -n "${DIFF_BASELINE}" ]]; then
  python3 scripts/api_surface.py "${JSON}" --diff "${DIFF_BASELINE}" \
    --diff-json "${DIFF_JSON}" > "${OUT}"
else
  python3 scripts/api_surface.py "${JSON}" > "${OUT}"
fi

echo "==> 完成：${OUT}（共 $(grep -vc '^#' "${OUT}" || true) 项）"
if [[ -n "${DIFF_BASELINE}" ]]; then
  echo "==> 结构化差异：${DIFF_JSON}"
fi
