#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 对比当前 criterion 结果与基线，输出回归方向与阈值判定。
#
# 基线来源（按优先级）：
#   1. BASELINE_MD 指定的已归档 markdown 基线（docs/benchmarks/*.md）——入库产物，
#      克隆仓库即可对比，不依赖本地 criterion 基线目录；
#   2. 本地 criterion 基线（target/criterion/**/<BASELINE>/estimates.json，不入库）；
#   3. 未显式指定 BASELINE_MD 且本地无 criterion 基线时，自动在 docs/benchmarks/
#      找「基线名称」与 BASELINE 匹配的归档 markdown。
#
# 用法：
#   bash scripts/perf_compare.sh                         # 默认基线 v1.0-pre，阈值 10%
#   BASELINE=v1.0-pre THRESHOLD=5 bash scripts/perf_compare.sh
#   BASELINE_MD=docs/benchmarks/v1.0-baseline.md bash scripts/perf_compare.sh
#   bash scripts/perf_compare.sh --help
#
# 产物：
#   logs/perf-compare.md    criterion 原始输出 + 汇总表
#   target/criterion/       criterion 原始 JSON（不入库）
#
# 退出码：0 = 无超阈值回归；1 = 存在超阈值回归；2 = 无可比数据/采集失败/基线解析失败。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

usage() {
    cat <<'USAGE'
用法：bash scripts/perf_compare.sh [选项]

选项：
  --help              输出本用法并退出 0（不触发 benchmark 采集）
  --baseline <name>   基线名称（等价环境变量 BASELINE，默认 v1.0-pre）
  --threshold <pct>   回归阈值百分比（等价环境变量 THRESHOLD，默认 10）
  --baseline-md <md>  指定已归档 markdown 基线（等价环境变量 BASELINE_MD）

基线来源优先级：--baseline-md > 本地 criterion 基线 > docs/benchmarks/ 自动匹配的归档基线。

产物：
  logs/perf-compare.md   criterion 原始输出 + 对比汇总表

退出码：
  0  无超阈值回归
  1  存在超阈值回归
  2  无可比数据 / 采集失败 / 基线解析失败
USAGE
}

BASELINE="${BASELINE:-v1.0-pre}"
THRESHOLD="${THRESHOLD:-10}"
OUT="${OUT:-logs/perf-compare.md}"
BASELINE_MD="${BASELINE_MD:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
    --help | -h)
        usage
        exit 0
        ;;
    --baseline)
        [[ $# -ge 2 ]] || {
            echo "ERROR: --baseline 缺少参数" >&2
            exit 2
        }
        BASELINE="$2"
        shift 2
        ;;
    --threshold)
        [[ $# -ge 2 ]] || {
            echo "ERROR: --threshold 缺少参数" >&2
            exit 2
        }
        THRESHOLD="$2"
        shift 2
        ;;
    --baseline-md)
        [[ $# -ge 2 ]] || {
            echo "ERROR: --baseline-md 缺少参数" >&2
            exit 2
        }
        BASELINE_MD="$2"
        shift 2
        ;;
    *)
        echo "ERROR: 未知参数: $1（--help 查看用法）" >&2
        exit 2
        ;;
    esac
done

if [[ ! "${THRESHOLD}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "ERROR: THRESHOLD 必须是数字: ${THRESHOLD}" >&2
    exit 2
fi

# 本地 criterion 基线是否存在（任意深度的 <BASELINE>/estimates.json）
local_baseline_count=0
if [[ -d target/criterion ]]; then
    local_baseline_count="$(find target/criterion -mindepth 2 -type f \
        -path "*/${BASELINE}/estimates.json" 2>/dev/null | wc -l | tr -d ' ')"
fi

# 基线来源判定：显式 md > 本地 criterion 基线 > 自动匹配归档 md
if [[ -n "${BASELINE_MD}" ]]; then
    if [[ ! -f "${BASELINE_MD}" ]]; then
        echo "ERROR: 指定的基线 markdown 不存在: ${BASELINE_MD}" >&2
        exit 2
    fi
    BASELINE_SOURCE="md"
elif [[ "${local_baseline_count}" -gt 0 ]]; then
    BASELINE_SOURCE="local"
else
    BASELINE_SOURCE="md-auto"
fi

if [[ "${BASELINE_SOURCE}" == "md" ]]; then
    BASELINE_MD_PATH="${BASELINE_MD}"
elif [[ "${BASELINE_SOURCE}" == "md-auto" ]]; then
    # 采集前先定位归档基线：找不到就在跑 benchmark 之前显性失败（退出码 2），
    # 不让「无基线」拖成一次几分钟的无效采集
    BASELINE_MD_PATH=""
    BASELINE_MARKER="- 基线名称：\`${BASELINE}\`"
    for candidate in docs/benchmarks/*.md; do
        [[ -f "${candidate}" ]] || continue
        if grep -qF -- "${BASELINE_MARKER}" "${candidate}"; then
            BASELINE_MD_PATH="${candidate}"
            break
        fi
    done
    if [[ -z "${BASELINE_MD_PATH}" ]]; then
        echo "ERROR: docs/benchmarks/ 中找不到基线名称为 \`${BASELINE}\` 的归档基线；" \
            "可用 BASELINE_MD=<path> 显式指定" >&2
        exit 2
    fi
else
    BASELINE_MD_PATH=""
fi

mkdir -p logs

{
    echo "# Garrison 性能对比"
    echo
    echo "- 采集时间（UTC）：$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "- 基线名称：\`${BASELINE}\`"
    echo "- 基线来源：${BASELINE_SOURCE}"
    echo "- 回归阈值：${THRESHOLD}%"
    echo "- git：\`$(git rev-parse HEAD 2>/dev/null || echo unknown)\`"
    echo "- rustc：\`$(rustc -V 2>/dev/null | head -n1 || echo unknown)\`"
    echo
    echo "## criterion 输出"
    echo
    echo '```text'
} >"${OUT}"

set +e
RUN_STARTED_AT="$(date +%s)"
if [[ "${BASELINE_SOURCE}" == "local" ]]; then
    cargo bench --features full --bench garrison_benchmark -- \
        --baseline "${BASELINE}" 2>&1 | tee -a "${OUT}"
else
    # 归档基线路径下本地无 criterion 基线可比：只采集当前值，由汇总表做差分。
    # 采集前清掉上次运行残留的 new/：criterion 的 new/ 在每个基准目录
    # （target/criterion/<group>/<id>/new/）下，残留会被 load_current 当成
    # 本次结果——被改名/跳过/中断的基准照样进对比表，门禁假绿。
    find target/criterion -type d -name new -prune -exec rm -rf {} + 2>/dev/null || true
    cargo bench --features full --bench garrison_benchmark -- 2>&1 | tee -a "${OUT}"
fi
BENCH_STATUS=${PIPESTATUS[0]}
set -e

{
    echo '```'
    echo
    echo "## 汇总"
    echo
} >>"${OUT}"

if [[ "${BENCH_STATUS}" -ne 0 ]]; then
    echo "criterion 采集失败（退出码 ${BENCH_STATUS}），无法对比。" | tee -a "${OUT}" >&2
    exit 2
fi

set +e
python3 - "${BASELINE}" "${THRESHOLD}" "${BASELINE_SOURCE}" "${BASELINE_MD_PATH}" <<'PY' | tee -a "${OUT}"
from __future__ import annotations

import json
import pathlib
import re
import sys

baseline = sys.argv[1]
threshold = float(sys.argv[2])
source = sys.argv[3]
md_path = sys.argv[4]
root = pathlib.Path("target/criterion")

# 归档 markdown 基线的 criterion 输出格式：
#   <name>              time:   [2.0106 ms 2.1222 ms 2.2174 ms]   （名称与时间同行）
#   <name>
#                         time:   [2.0285 ms 2.1528 ms 2.2607 ms]   （名称过长时名称独占一行）
TIME_RE = re.compile(r"time:\s*\[([^\]]+)\]")
UNIT_TO_MS = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "μs": 1e-3, "ms": 1.0, "s": 1e3}


def parse_md_baseline(path: pathlib.Path) -> dict[str, float]:
    """从归档 markdown 基线解析 {benchmark 组名: 均值(ms)}。

    只读「## criterion 输出」小节的 ```text 代码块，避免把环境信息等
    其他文本误当作基准数据。解析不出任何条目时抛错——静默当作空基线会把
    「无法对比」误报成「无回归」。
    """
    text = path.read_text(encoding="utf-8")
    section = re.search(
        r"^##\s*criterion\s*输出\s*$", text, flags=re.MULTILINE
    )
    if section is None:
        raise ValueError(f"归档基线缺少「## criterion 输出」小节: {path}")
    tail = text[section.end():]
    fence = re.search(r"```text\n(.*?)```", tail, flags=re.DOTALL)
    if fence is None:
        raise ValueError(f"归档基线的「## criterion 输出」小节缺少 ```text 代码块: {path}")

    rows: dict[str, float] = {}
    skipped: list[str] = []
    previous: str | None = None
    for line in fence.group(1).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = TIME_RE.search(line)
        if match is None:
            if not stripped.startswith("Benchmarking"):
                previous = stripped
            continue
        name = line[: match.start()].strip()
        if not name:
            name = previous or ""
        previous = None
        if not name or name.startswith("Benchmarking"):
            continue
        parts = match.group(1).split()
        if len(parts) < 6:
            skipped.append(stripped)
            continue
        try:
            mean = float(parts[2])
        except ValueError:
            skipped.append(stripped)
            continue
        unit = parts[3]
        factor = UNIT_TO_MS.get(unit)
        if factor is None:
            skipped.append(stripped)
            continue
        rows[name] = mean * factor
    if not rows:
        raise ValueError(f"归档基线未解析出任何基准条目: {path}")
    if skipped:
        raise ValueError(
            f"归档基线有 {len(skipped)} 行无法解析（格式变更会静默缩小可比面）: {path}；"
            f"首行: {skipped[0]!r}"
        )
    return rows


def load_local_baseline() -> dict[str, float]:
    """本地 criterion 基线：{组名: 均值(ms)}。"""
    rows: dict[str, float] = {}
    for path in root.rglob(f"{baseline}/estimates.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            mean = float(data["mean"]["point_estimate"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        rows[str(path.parent.parent.relative_to(root))] = mean / 1e6
    return rows


def load_current() -> dict[str, float]:
    """当前采集结果：{组名: 均值(ms)}。"""
    rows: dict[str, float] = {}
    for path in root.rglob("new/estimates.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            mean = float(data["mean"]["point_estimate"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        rows[str(path.parent.parent.relative_to(root))] = mean / 1e6
    return rows


def load_current_md_compatible() -> dict[str, float]:
    """当前采集结果（median 口径）：与归档 markdown 基线同一统计量。

    归档基线 parse 的是 criterion 终端输出 time: [lo typical hi] 的中间值
    （typical = median）；当前侧若读 mean，则 median 基线 vs mean 当前
    两个统计量混比，噪声大的基准会假报/漏报回归。md 口径统一取 median。
    """
    rows: dict[str, float] = {}
    for path in root.rglob("new/estimates.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            median = float(data["median"]["point_estimate"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        rows[str(path.parent.parent.relative_to(root))] = median / 1e6
    return rows


def discover_md_baseline(name: str) -> pathlib.Path:
    """在 docs/benchmarks/ 中找「基线名称」与 name 匹配的归档 markdown。"""
    candidates = sorted(pathlib.Path("docs/benchmarks").glob("*.md"))
    for candidate in candidates:
        text = candidate.read_text(encoding="utf-8")
        found = re.search(r"^- 基线名称：`([^`]+)`\s*$", text, flags=re.MULTILINE)
        if found and found.group(1) == name:
            return candidate
    available = ", ".join(path.name for path in candidates) or "(无)"
    raise ValueError(
        f"docs/benchmarks/ 中找不到基线名称为 `{name}` 的归档基线（现有: {available}）；"
        f"可用 BASELINE_MD=<path> 显式指定"
    )


try:
    if source == "local":
        base_rows = load_local_baseline()
        current_rows = load_current()
    else:
        md = pathlib.Path(md_path) if md_path else discover_md_baseline(baseline)
        base_rows = parse_md_baseline(md)
        current_rows = load_current_md_compatible()
except ValueError as error:
    print(f"基线解析失败：{error}")
    raise SystemExit(2)

if not base_rows:
    print(f"未找到与基线 `{baseline}` 可比的数据；请先运行 scripts/perf_baseline.sh。")
    raise SystemExit(2)
if not current_rows:
    print("未采集到当前基准数据（target/criterion 下无 new/estimates.json）；采集失败。")
    raise SystemExit(2)

rows: list[tuple[str, float, float, float]] = []
for name, base_ms in base_rows.items():
    new_ms = current_rows.get(name)
    if new_ms is None or base_ms <= 0:
        continue
    rows.append((name, base_ms, new_ms, (new_ms - base_ms) / base_ms * 100.0))

if not rows:
    print(
        f"基线 `{baseline}` 与当前采集结果没有同名基准可比；"
        f"基线条目 {len(base_rows)} 个、当前条目 {len(current_rows)} 个。"
    )
    raise SystemExit(2)

rows.sort(key=lambda row: row[3], reverse=True)
print("| benchmark | baseline (ms) | current (ms) | change |")
print("|---|---:|---:|---:|")
for name, base_ms, new_ms, change in rows:
    flag = " **REGRESSION**" if change > threshold else ""
    print(f"| `{name}` | {base_ms:.3f} | {new_ms:.3f} | {change:+.2f}%{flag} |")

missing = sorted(set(base_rows) - set(current_rows))
added = sorted(set(current_rows) - set(base_rows))
if missing:
    print()
    print(f"基线中有但本次未采集到（基准被删除或改名）：{', '.join(f'`{n}`' for n in missing)}")
    print("判定：可比面不完整（missing > 0），按失败处理——部分基线未验证不能判绿。")
    raise SystemExit(2)
if added:
    print()
    print(f"本次新增且基线中无（无基线可比，不计入回归判定）：{', '.join(f'`{n}`' for n in added)}")

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
