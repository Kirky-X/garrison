#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 对比当前 criterion 结果与已存档基线，输出回归方向与阈值判定。
#
# 用法：
#   bash scripts/perf_compare.sh                         # 默认基线 v1.0-pre，阈值 10%
#   BASELINE=v1.0-pre THRESHOLD=5 bash scripts/perf_compare.sh
#
# 产物：
#   logs/perf-compare.md    criterion 原始输出 + 汇总表
#   target/criterion/       criterion 原始 JSON（不入库）
#
# 退出码：0 = 无超阈值回归；1 = 存在超阈值回归；2 = 无可比数据/采集失败。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

BASELINE="${BASELINE:-v1.0-pre}"
THRESHOLD="${THRESHOLD:-10}"
OUT="${OUT:-logs/perf-compare.md}"

mkdir -p logs

{
  echo "# Garrison 性能对比"
  echo
  echo "- 采集时间（UTC）：$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "- 基线名称：\`${BASELINE}\`"
  echo "- 回归阈值：${THRESHOLD}%"
  echo "- git：\`$(git rev-parse HEAD 2>/dev/null || echo unknown)\`"
  echo "- rustc：\`$(rustc -V 2>/dev/null | head -n1 || echo unknown)\`"
  echo
  echo "## criterion 输出"
  echo
  echo '```text'
} > "${OUT}"

set +e
cargo bench --features full --bench garrison_benchmark -- \
  --baseline "${BASELINE}" 2>&1 | tee -a "${OUT}"
BENCH_STATUS=${PIPESTATUS[0]}
set -e

{
  echo '```'
  echo
  echo "## 汇总"
  echo
} >> "${OUT}"

if [[ "${BENCH_STATUS}" -ne 0 ]]; then
  echo "criterion 采集失败（退出码 ${BENCH_STATUS}），无法对比。" | tee -a "${OUT}" >&2
  exit 2
fi

set +e
python3 - "${BASELINE}" "${THRESHOLD}" <<'PY' | tee -a "${OUT}"
from __future__ import annotations

import json
import pathlib
import sys

baseline = sys.argv[1]
threshold = float(sys.argv[2])
root = pathlib.Path("target/criterion")

rows: list[tuple[str, float, float, float]] = []
for new_path in root.rglob("new/estimates.json"):
    bench_dir = new_path.parent.parent
    base_path = bench_dir / baseline / "estimates.json"
    if not base_path.is_file():
        continue
    try:
        new = json.loads(new_path.read_text(encoding="utf-8"))
        base = json.loads(base_path.read_text(encoding="utf-8"))
        new_mean = float(new["mean"]["point_estimate"])
        base_mean = float(base["mean"]["point_estimate"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        continue
    if base_mean <= 0:
        continue
    change = (new_mean - base_mean) / base_mean * 100.0
    name = str(bench_dir.relative_to(root))
    rows.append((name, base_mean / 1e6, new_mean / 1e6, change))

if not rows:
    print(f"未找到与基线 `{baseline}` 可比的数据；请先运行 scripts/perf_baseline.sh。")
    raise SystemExit(2)

rows.sort(key=lambda row: row[3], reverse=True)
print("| benchmark | baseline (ms) | current (ms) | change |")
print("|---|---:|---:|---:|")
for name, base_ms, new_ms, change in rows:
    flag = " **REGRESSION**" if change > threshold else ""
    print(f"| `{name}` | {base_ms:.3f} | {new_ms:.3f} | {change:+.2f}%{flag} |")

regressions = [row for row in rows if row[3] > threshold]
print()
if regressions:
    print(f"判定：{len(regressions)} 项超过 +{threshold:.0f}% 回归阈值。")
    raise SystemExit(1)
print(f"判定：无超过 +{threshold:.0f}% 的回归。")
PY
PY_STATUS=${PIPESTATUS[0]}
set -e

echo "==> 完成：${OUT}"
exit "${PY_STATUS}"
