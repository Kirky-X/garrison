#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# archive_change.sh — specmark 归档执行器（确定性逻辑代码化，规则5）
#
# 依据 specmark/references/archive.md Step 5 的归档流程。包含：
#   - 归档目录只读哨兵（.readonly）
#   - change 级独占 flock（防并发损坏）
#   - 只读强制（目标已存在时拒绝覆盖）
#   - --sync 时调用 merge_delta_spec.py 同步 delta spec 到主 specs
#   - 原子 mv changes/<name> → archive/<date>-<name>
#   - 写 meta.json（commit SHA 锚定）
#
# 用法：
#   bash scripts/archive_change.sh <name> [--sync] [--date YYYY-MM-DD]
#
# 退出码：
#   0 — 成功
#   1 — 一般错误（参数错误 / 产物缺失 / mv 失败 / 目标已存在）
#   2 — flock 竞争超时
#
# Copyright (c) 2024-2026 Kirky.X. See LICENSE for full license text.

set -euo pipefail

# ============================================================================
# 配置与路径
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SPECMARK_DIR="${PROJECT_ROOT}/specmark"
CHANGES_DIR="${SPECMARK_DIR}/changes"
ARCHIVE_DIR="${SPECMARK_DIR}/archive"
SPECS_DIR="${SPECMARK_DIR}/specs"
LOCKS_DIR="${SPECMARK_DIR}/.locks"
READONLY_SENTINEL="${ARCHIVE_DIR}/.readonly"

MERGE_SCRIPT="${SCRIPT_DIR}/merge_delta_spec.py"

# ============================================================================
# 参数解析
# ============================================================================

CHANGE_NAME=""
DO_SYNC=false
ARCHIVE_DATE=""

usage() {
    cat <<EOF
用法: bash scripts/archive_change.sh <name> [--sync] [--date YYYY-MM-DD]

参数:
  <name>                    要归档的变更名（specmark/changes/<name>）
  --sync                    同步 delta spec 到主 specs（调用 merge_delta_spec.py）
  --date YYYY-MM-DD         指定归档日期（默认 UTC 今天）

退出码:
  0 — 成功
  1 — 一般错误
  2 — flock 竞争超时
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sync)
            DO_SYNC=true
            shift
            ;;
        --date)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --date 需要参数 YYYY-MM-DD" >&2
                exit 1
            fi
            ARCHIVE_DATE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "${CHANGE_NAME}" ]]; then
                CHANGE_NAME="$1"
            else
                echo "ERROR: 未知参数 '$1'" >&2
                usage >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "${CHANGE_NAME}" ]]; then
    echo "ERROR: 缺少变更名参数" >&2
    usage >&2
    exit 1
fi

# 默认日期：UTC 今天
if [[ -z "${ARCHIVE_DATE}" ]]; then
    ARCHIVE_DATE="$(date -u +%Y-%m-%d)"
fi

CHANGE_DIR="${CHANGES_DIR}/${CHANGE_NAME}"
ARCHIVE_TARGET="${ARCHIVE_DIR}/${ARCHIVE_DATE}-${CHANGE_NAME}"

# ============================================================================
# 前置检查
# ============================================================================

echo "[archive] 变更: ${CHANGE_NAME}"
echo "[archive] 日期: ${ARCHIVE_DATE}"
echo "[archive] 同步: ${DO_SYNC}"
echo ""

# 检查变更目录存在
if [[ ! -d "${CHANGE_DIR}" ]]; then
    echo "ERROR: 变更目录不存在: ${CHANGE_DIR}" >&2
    exit 1
fi

# 检查产物文件
MISSING_ARTIFACTS=()
for artifact in proposal.md design.md tasks.md; do
    if [[ ! -f "${CHANGE_DIR}/${artifact}" ]]; then
        MISSING_ARTIFACTS+=("${artifact}")
    fi
done
if [[ ${#MISSING_ARTIFACTS[@]} -gt 0 ]]; then
    echo "WARNING: 缺失产物文件: ${MISSING_ARTIFACTS[*]}" >&2
fi

# 检查 delta specs 目录
DELTA_SPECS_DIR="${CHANGE_DIR}/specs"
HAS_DELTA_SPECS=false
if [[ -d "${DELTA_SPECS_DIR}" ]]; then
    # 检查是否有 .md 文件
    DELTA_SPEC_COUNT=$(find "${DELTA_SPECS_DIR}" -name '*.md' -type f | wc -l)
    if [[ "${DELTA_SPEC_COUNT}" -gt 0 ]]; then
        HAS_DELTA_SPECS=true
    fi
fi

if [[ "${DO_SYNC}" == "true" && "${HAS_DELTA_SPECS}" == "false" ]]; then
    echo "WARNING: --sync 已传入但无 delta spec，跳过同步" >&2
    DO_SYNC=false
fi

echo "[archive] delta specs: ${DELTA_SPEC_COUNT:-0} 个"
echo ""

# ============================================================================
# 只读哨兵初始化
# ============================================================================

# 创建归档目录（若不存在）
mkdir -p "${ARCHIVE_DIR}"

# 创建只读哨兵（若不存在）
if [[ ! -f "${READONLY_SENTINEL}" ]]; then
    cat > "${READONLY_SENTINEL}" <<'EOF'
# specmark/archive/ 只读哨兵
# 此目录是只读历史。既有归档条目禁止修改/删除/重命名，只允许追加新条目。
# 修改请新建 change 处理后续变更。
EOF
    echo "[archive] 创建只读哨兵: ${READONLY_SENTINEL}"
fi

# ============================================================================
# 只读强制检查：目标归档目录是否已存在
# ============================================================================

if [[ -e "${ARCHIVE_TARGET}" ]]; then
    echo "ERROR: 归档目标已存在，拒绝覆盖（只读强制）: ${ARCHIVE_TARGET}" >&2
    echo "  如需重新归档，请使用 --date 指定不同日期，或先删除现有归档（不推荐）。" >&2
    exit 1
fi

# ============================================================================
# change 级独占 flock
# ============================================================================

mkdir -p "${LOCKS_DIR}"
LOCK_FILE="${LOCKS_DIR}/${CHANGE_NAME}.lock"
exec 9>"${LOCK_FILE}"

if ! flock -w 10 -x 9; then
    echo "ERROR: 无法获取 change 级锁（超时 10s）: ${LOCK_FILE}" >&2
    echo "  可能有其他进程正在归档此变更。请稍后重试。" >&2
    exit 2
fi
echo "[archive] 获取 change 级锁: ${LOCK_FILE}"

# ============================================================================
# delta spec 同步（--sync）
# ============================================================================

SYNCED_COUNT=0
SYNCED_CAPS=()

if [[ "${DO_SYNC}" == "true" ]]; then
    echo ""
    echo "[archive] === delta spec 同步 (--sync) ==="

    while IFS= read -r -d '' delta_file; do
        # delta 父目录名 → main spec 目录名
        # delta 路径结构：specs/<capability>/spec.md，capability = spec.md 的父目录名
        cap_name="$(basename "$(dirname "${delta_file}")")"
        main_spec="${SPECS_DIR}/${cap_name}/spec.md"

        echo "[archive] 同步: ${cap_name}"
        echo "  delta: ${delta_file}"
        echo "  main:  ${main_spec}"

        if python3 "${MERGE_SCRIPT}" \
            --main "${main_spec}" \
            --delta "${delta_file}"; then
            SYNCED_COUNT=$((SYNCED_COUNT + 1))
            SYNCED_CAPS+=("${cap_name}")
        else
            echo "ERROR: merge_delta_spec.py 失败 (exit $?) for ${cap_name}" >&2
            exit 1
        fi
    done < <(find "${DELTA_SPECS_DIR}" -name '*.md' -type f -print0 | sort -z)

    echo "[archive] 同步完成: ${SYNCED_COUNT} 个 capability"
    echo ""
fi

# ============================================================================
# 原子 mv changes/<name> → archive/<date>-<name>
# ============================================================================

echo "[archive] === 归档迁移 ==="
echo "  源:   ${CHANGE_DIR}"
echo "  目标: ${ARCHIVE_TARGET}"

mv "${CHANGE_DIR}" "${ARCHIVE_TARGET}"
echo "[archive] mv 完成"

# ============================================================================
# 写 meta.json（commit SHA 锚定）
# ============================================================================

# 获取 git HEAD SHA（或 null）
COMMIT_SHA="null"
if git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    COMMIT_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD 2>/dev/null || echo "null")"
fi

META_FILE="${ARCHIVE_TARGET}/meta.json"
cat > "${META_FILE}" <<EOF
{
  "change": "${CHANGE_NAME}",
  "archived_at": "${ARCHIVE_DATE}",
  "commit_sha": "${COMMIT_SHA}",
  "synced": ${DO_SYNC}
}
EOF

echo "[archive] meta.json 已写入: ${META_FILE}"

# ============================================================================
# 释放锁
# ============================================================================

flock -u 9
exec 9>&-

# ============================================================================
# 摘要
# ============================================================================

echo ""
echo "========================================"
echo "归档完成"
echo "========================================"
echo "变更:       ${CHANGE_NAME}"
echo "归档到:     ${ARCHIVE_TARGET}"
echo "Commit SHA: ${COMMIT_SHA}"
if [[ "${DO_SYNC}" == "true" ]]; then
    echo "Delta Specs: ✓ 已同步 ${SYNCED_COUNT} 个 capability 到主 specs"
    for cap in "${SYNCED_CAPS[@]}"; do
        echo "             - ${cap}"
    done
else
    echo "Delta Specs: 随变更归档（未同步）"
fi
echo "========================================"

exit 0
