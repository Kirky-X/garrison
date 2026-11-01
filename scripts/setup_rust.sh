#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 安装并选定 Rust 工具链（替代 dtolnay/rust-toolchain action）。
#
# 用法：scripts/setup_rust.sh <toolchain> [components...]
#   toolchain   工具链规格：1.97.1 / stable / beta / nightly / nightly-YYYY-MM-DD
#               只接受字面版本与通道名。action 支持的 "stable N days ago" /
#               "1.x" 等模糊写法在此不支持：模糊写法随日期漂移，与本仓
#               Reproducible Build 门禁的可复现要求冲突。
#   components  可选组件（rustfmt clippy ...），逗号或空格分隔。
#
# 为何不用 dtolnay/rust-toolchain：
#   该 action 仓库全仓只有 1 个 tag（v1）、没有任何版本 tag，且每次 Rust 发布都会
#   force-push 重写全部分支快照。按 SHA 钉它的结果必然脱离上游 ref 历史——zizmor
#   的 impostor-commit（要求可达）与 stale-action-refs（要求指向 tag）两条规则
#   结构性不可满足，且每 6 周随上游重写复发一次。runner 预装 rustup，直接用 rustup
#   既根治误报，供应链面也同时少一个第三方 action。
#
# 语义对齐被移除的 action（dtolnay/rust-toolchain 的 composite 步骤）：
#   安装(--profile minimal) → 装组件 → 设为默认 → 关增量编译 → 开彩色输出。
#   另写 RUSTUP_TOOLCHAIN：显式钉住工具链，不受将来目录级 rust-toolchain.toml 覆盖
#   影响（该文件曾因目录级 channel="stable" 静默覆盖所有 workflow pin 而被删除，
#   见 docs/CHANGELOG.md）。
#
# 退出码：0 = 成功；2 = 参数错误；其余为 rustup 失败码。

set -euo pipefail

TOOLCHAIN="${1:-}"
if [[ -z "$TOOLCHAIN" ]]; then
  echo "用法：scripts/setup_rust.sh <toolchain> [components...]" >&2
  exit 2
fi
shift

COMPONENTS="${*:-}"

echo "[setup-rust] 工具链: $TOOLCHAIN${COMPONENTS:+ / 组件: $COMPONENTS}"

# 分量按逗号与空白切分，禁用 glob 展开（对齐 action 的 `set -f`）。
set -f
flags=()
for c in ${COMPONENTS//,/ }; do
  flags+=(--component "$c")
done
# nightly 组件可能比已装的 nightly 旧，需允许降级（对齐 action）。
if [[ "$TOOLCHAIN" == nightly && ${#flags[@]} -gt 0 ]]; then
  flags+=(--allow-downgrade)
fi
set +f

# 官方发布服务器更新期间可能校验和失败，重试（对齐 action 的 5 次重试）。
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
status=0
for attempt in 1 2 3 4 5; do
  if RUSTUP_PERMIT_COPY_RENAME=1 rustup toolchain install "$TOOLCHAIN" "${flags[@]}" \
      --profile minimal --no-self-update --force-non-host 2>&1 | tee "$log"; then
    status=0
    break
  else
    status=$?
  fi
  if [[ $attempt -eq 5 ]] \
      || ! grep -Fq 'checksum failed for ' "$log" \
      || ! grep -Fq 'this is likely due to an ongoing update of the official release server' "$log"; then
    exit "$status"
  fi
  echo "[setup-rust] 校验和失败（发布服务器更新中），30 秒后重试（第 $attempt 次，共 5 次）" >&2
  sleep 30
done

# 设为默认。与 action 不同，这里不吞掉失败：默认工具链没切过去，后续 cargo 会
# 静默用 runner 预装的 stable 编译——那正是本仓最忌讳的静默版本漂移。
if ! rustup default "$TOOLCHAIN" --force-non-host; then
  echo "[setup-rust] 错误：无法将 $TOOLCHAIN 设为默认工具链" >&2
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  # 显式钉住工具链：后续步骤的 cargo/rustc 必定走该工具链，
  # 不受目录级 rust-toolchain.toml 影响。
  echo "RUSTUP_TOOLCHAIN=$TOOLCHAIN" >>"$GITHUB_ENV"
  # 关闭增量编译（action 同款）：CI 全量构建不需要增量产物。
  if [[ -z "${CARGO_INCREMENTAL+set}" ]]; then
    echo "CARGO_INCREMENTAL=0" >>"$GITHUB_ENV"
  fi
  # 强制彩色输出（action 同款），仅在调用方未设置时生效。
  if [[ -z "${CARGO_TERM_COLOR+set}" ]]; then
    echo "CARGO_TERM_COLOR=always" >>"$GITHUB_ENV"
  fi
fi

echo "[setup-rust] 已选定: $(rustc +"$TOOLCHAIN" --version)"
