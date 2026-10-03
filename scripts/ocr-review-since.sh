#!/usr/bin/env bash
# ocr-review-since.sh — 以 logs/ 下最新 OCR 报告文件时间为基准，对其后的新增
# commit 做分块 AI 代码审查（open-code-review / ocr）。
#
# 用法：
#   scripts/ocr-review-since.sh [--dry-run] [--chunks N] [--base <git-ref>] [--since '<datetime>']
#
# 默认行为：
#   1. 基准时间 = logs/ocr* 最新文件的 mtime（可用 --since 覆盖）；
#   2. 找出该时间之后 main 上的全部 commit（可用 --base <ref> 改为审查 <ref>..HEAD）；
#   3. 按 --chunks（默认 3）均分为时间块，逐块执行 `ocr review --from <块起点> --to <块终点>`；
#   4. 报告写入 logs/ocr_review_<UTC时间戳>_chunk<N>.md，并汇总到 logs/ocr_review_<UTC时间戳>_summary.md。
#
# 前置：ocr 已安装且已配置 provider/model（`ocr config provider`；本项目用
# custom provider agnes = apihub.agnes-ai.com openai 协议）。
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

DRY_RUN=0
CHUNKS=3
BASE_REF=""
SINCE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --chunks) CHUNKS="$2"; shift ;;
        --base) BASE_REF="$2"; shift ;;
        --since) SINCE="$2"; shift ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
    shift
done

command -v ocr >/dev/null || { echo "错误: 未安装 ocr（npm i -g @alibaba-group/open-code-review）" >&2; exit 1; }

# 基准时间：logs/ 下最新 ocr* 文件的 mtime（排除本脚本自身产物 ocr_review*，
# 否则运行日志/报告会把基准顶成「现在」，导致窗口恒为空）
if [[ -z "$SINCE" ]]; then
    latest_ocr_log=$(ls -t --time-style=+%Y-%m-%d\ %H:%M:%S -l logs/ocr* 2>/dev/null | grep -vE 'ocr_review' | head -1 | awk '{print $6, $7}')
    [[ -n "$latest_ocr_log" ]] || { echo "错误: logs/ 下无 ocr* 文件，请用 --since 指定基准时间" >&2; exit 1; }
    SINCE="$latest_ocr_log"
fi
echo "基准时间: $SINCE"

# 审查窗口：基准时间之前的最后一个 commit 为块 1 起点
BASE_REF=${BASE_REF:-$(git log --before="$SINCE" -1 --format=%H)}
[[ -n "$BASE_REF" ]] || { echo "错误: 基准时间之前无 commit" >&2; exit 1; }
base_subject=$(git log -1 --format='%h %ad %s' --date=format:'%Y-%m-%d %H:%M' "$BASE_REF")
echo "窗口起点: $base_subject"

# 新增 commit（旧→新）
mapfile -t commits < <(git rev-list "${BASE_REF}..main" | tac)
total=${#commits[@]}
if (( total == 0 )); then
    echo "无新增 commit，退出"
    exit 0
fi
echo "新增 commit: $total 个，分 $CHUNKS 块审查"

# 均分块终点（旧→新）
size=$(( (total + CHUNKS - 1) / CHUNKS ))
starts=()
ends=()
prev="$BASE_REF"
for ((i = 0; i < total; i += size)); do
    end_idx=$((i + size - 1))
    (( end_idx > total - 1 )) && end_idx=$((total - 1))
    starts+=("$prev")
    ends+=("${commits[end_idx]}")
    prev="${commits[end_idx]}"
done

stamp=$(date -u +%Y%m%d%H%M%S)
summary="logs/ocr_review_${stamp}_summary.md"
: > "$summary"

for i in "${!starts[@]}"; do
    n=$((i + 1))
    from="${starts[i]}"
    to="${ends[i]}"
    from_short=$(git log -1 --format='%h(%ad)' --date=format:'%m-%d %H:%M' "$from")
    to_short=$(git log -1 --format='%h(%ad) %s' --date=format:'%m-%d %H:%M' "$to")
    count=$(git rev-list "${from}..${to}" | wc -l)
    echo "---- 块 $n/${#starts[@]}: ${from_short} → ${to_short}（${count} commits）----"

    if (( DRY_RUN )); then
        echo "[dry-run] ocr review --from $from --to $to"
        continue
    fi

    report="logs/ocr_review_${stamp}_chunk${n}.md"
    {
        echo "# OCR 代码审查报告 — 块 $n"
        echo ""
        echo "- 范围: \`${from_short}\` → \`${to_short}\`（${count} commits）"
        echo "- 基准: logs/ 最新 ocr 文件时间 $SINCE"
        echo "- 工具: ocr $(ocr version 2>/dev/null | head -1) / model: $(ocr config get model 2>/dev/null || echo '见 ocr config')"
        echo "- 生成: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    } > "$report"
    ocr review --from "$from" --to "$to" >> "$report" 2>"logs/ocr_review_${stamp}_chunk${n}.stderr.log"
    echo "  报告: $report（$(wc -l < "$report") 行）"
    {
        echo "## 块 $n: ${from_short} → ${to_short}（${count} commits）"
        echo "报告: $report"
        echo ""
    } >> "$summary"
done

if (( ! DRY_RUN )); then
    echo "汇总: $summary"
fi
