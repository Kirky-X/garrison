#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 采集安全审计证据摘要（v1.0 安全审计门禁的启动材料）。
#
# 用法：
#   bash scripts/security_evidence.sh
#
# 产物：
#   logs/security-evidence.md          汇总（工具 × 状态 × 日志路径）
#   logs/security-evidence/*.log       各工具原始输出
#
# 说明：工具缺失时显式 SKIP，不静默失败；CodeQL / fuzz 深扫在 CI 执行，本脚本只做本地可复现项。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

OUT="logs/security-evidence.md"
EVIDENCE_DIR="logs/security-evidence"
mkdir -p "${EVIDENCE_DIR}"

ROWS=()

record_skip() {
  local name="$1" reason="$2"
  ROWS+=("| ${name} | — | SKIP（${reason}） | — |")
}

run_step() {
  local name="$1" cmd="$2"
  local log="${EVIDENCE_DIR}/${name}.log"
  echo "==> ${name}: ${cmd}"
  if bash -c "${cmd}" >"${log}" 2>&1; then
    ROWS+=("| ${name} | \`${cmd}\` | PASS | \`${log}\` |")
  else
    local status=$?
    ROWS+=("| ${name} | \`${cmd}\` | FAIL（exit ${status}） | \`${log}\` |")
  fi
}

# 网络不可用时回退到本地 advisory 缓存：区分「真实告警」与「仅拉取失败」。
run_step_with_offline_fallback() {
  local name="$1" primary="$2" fallback="$3"
  local log="${EVIDENCE_DIR}/${name}.log"
  local offline_log="${EVIDENCE_DIR}/${name}.offline.log"
  echo "==> ${name}: ${primary}（失败时回退: ${fallback}）"
  if bash -c "${primary}" >"${log}" 2>&1; then
    ROWS+=("| ${name} | \`${primary}\` | PASS | \`${log}\` |")
    return
  fi
  local primary_status=$?
  if bash -c "${fallback}" >"${offline_log}" 2>&1; then
    ROWS+=("| ${name} | \`${primary}\` 网络失败 → \`${fallback}\` | PASS（本地缓存） | \`${log}\` / \`${offline_log}\` |")
  else
    local fallback_status=$?
    ROWS+=("| ${name} | \`${primary}\` / \`${fallback}\` | FAIL（${primary_status}/${fallback_status}） | \`${log}\` / \`${offline_log}\` |")
  fi
}

# --- 依赖与策略（本地已安装概率最高） ---
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
  run_step_with_offline_fallback "cargo-audit" "cargo audit" "cargo audit --no-fetch"
else
  record_skip "cargo-audit" "未安装（cargo install cargo-audit）"
fi

if command -v cargo-deny >/dev/null 2>&1 || cargo deny --version >/dev/null 2>&1; then
  run_step_with_offline_fallback "cargo-deny" "cargo deny check" "CARGO_NET_OFFLINE=true cargo deny check"
else
  record_skip "cargo-deny" "未安装（cargo install cargo-deny）"
fi

if command -v cargo-vet >/dev/null 2>&1 || cargo vet --version >/dev/null 2>&1; then
  run_step "cargo-vet" "cargo vet --locked"
else
  record_skip "cargo-vet" "未安装（cargo install cargo-vet）"
fi

# --- SAST（可选） ---
if command -v semgrep >/dev/null 2>&1; then
  run_step "semgrep" "semgrep scan --config p/rust --config p/secrets --error --sarif --output ${EVIDENCE_DIR}/semgrep.sarif ."
else
  record_skip "semgrep" "未安装（pip install semgrep）"
fi

# --- CI-only 项：记录口径，不在本地强行执行 ---
ROWS+=("| CodeQL | \`.github/workflows/codeql.yml\` | CI | GitHub Security 告警 |")
ROWS+=("| fuzz（4 targets） | \`.github/workflows/fuzz-weekly.yml\` / \`security.yml\` | CI | \`fuzz/artifacts/\` |")
ROWS+=("| e2e 安全面 | \`bash scripts/e2e_run.sh\` | 手动/发布候选 | \`logs/e2e_final_report.md\` |")

{
  echo "# Garrison 安全审计证据摘要"
  echo
  echo "- 采集时间（UTC）：$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "- git：\`$(git rev-parse HEAD 2>/dev/null || echo unknown)\`"
  echo "- rustc：\`$(rustc -V 2>/dev/null | head -n1 || echo unknown)\`"
  echo "- 定位：本摘要为审计就绪材料，不是第三方审计报告；工具缺失显式 SKIP。"
  echo
  echo "| 证据 | 命令 | 状态 | 日志 |"
  echo "|------|------|------|------|"
  printf '%s\n' "${ROWS[@]}"
  echo
  echo "## 说明"
  echo
  echo "- \`cargo audit\` / \`cargo deny\` 需要网络拉取 advisory DB；失败时请重试并检查网络。"
  echo "- \`cargo vet\` 依赖 \`supply-chain/\` 配置；豁免项需有理由与复核日期。"
  echo "- CodeQL / fuzz / e2e 安全面在 CI 或发布候选流程执行，见 \`.github/workflows/\`。"
} > "${OUT}"

echo "==> 完成：${OUT}"
