#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
#
# 可复现构建验证（reproducible build）：对 garrison 库做两次独立编译，
# 比对产物 sha256 是否逐字节一致。
#
# 方法：
#   - 固定构建输入：--locked（锁定依赖）、--frozen（禁网络变更）、固定
#     SOURCE_DATE_EPOCH（防时间戳嵌入）、RUSTFLAGS --remap-path-prefix
#     （工作区绝对路径 → 固定前缀，消除本地路径差异）。
#   - 两次构建间 `cargo clean -p garrison` 只清理本 crate 产物（依赖缓存
#     复用，二次构建仅重编译 garrison 自身，分钟级）。
#   - 产物：target/release/libgarrison.rlib 的 sha256。
#
# 用法：
#   scripts/verify_reproducible_build.sh                 # 默认 default 特性
#   GARRISON_REPRO_FEATURES="full" scripts/verify_reproducible_build.sh
#
# 退出码：0 = 逐字节一致（可复现）；1 = 不一致或构建失败。
# 注意：更换 rustc 版本 / 依赖版本后需重跑（可复现性以「同工具链 + 同锁文件」
# 为前提，与 cargo vet / Attestations 的验证维度互补，见 docs/RELEASING.md）。

set -euo pipefail

FEATURES="${GARRISON_REPRO_FEATURES:-}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
ARTIFACT="$TARGET_DIR/release/libgarrison.rlib"
EPOCH="${GARRISON_REPRO_EPOCH:-1700000000}"

cd "$(dirname "$0")/.."

export SOURCE_DATE_EPOCH="$EPOCH"
export RUSTFLAGS="--remap-path-prefix=$PWD=/garrison"

# 只清理 garrison 自身的产物与指纹（依赖缓存复用，二次构建仅重编译本 crate）。
# 不用 `cargo clean -p garrison`：对 workspace 根包实测匹配不到产物（Removed 0 files）。
clean_garrison_artifacts() {
  rm -rf "$TARGET_DIR"/release/.fingerprint/garrison-* \
         "$TARGET_DIR"/release/deps/libgarrison-* \
         "$TARGET_DIR"/release/libgarrison.rlib \
         "$TARGET_DIR"/release/libgarrison.d \
         "$TARGET_DIR"/release/garrison-*
}

build_once() {
  local label="$1"
  # 标签走 stderr：stdout 仅输出哈希，供调用方 $(...) 捕获
  echo "[repro] 构建 $label（features=${FEATURES:-default}）..." >&2
  clean_garrison_artifacts
  if [[ -n "$FEATURES" ]]; then
    cargo build --lib --release --locked --frozen --features "$FEATURES" >&2
  else
    cargo build --lib --release --locked --frozen >&2
  fi
  sha256sum "$ARTIFACT" | awk '{print $1}'
}

echo "[repro] 工具链: $(rustc --version) / cargo $(cargo --version)"
echo "[repro] SOURCE_DATE_EPOCH=$EPOCH  RUSTFLAGS=$RUSTFLAGS"

H1="$(build_once "第 1 次")"
H2="$(build_once "第 2 次")"

echo "[repro] 第 1 次产物 sha256: $H1"
echo "[repro] 第 2 次产物 sha256: $H2"

if [[ "$H1" == "$H2" ]]; then
  echo "[repro] PASS：两次构建逐字节一致（可复现）"
  exit 0
else
  echo "[repro] FAIL：两次构建产物不一致——请检查是否引入了路径/时间/环境相关"
  echo "        的非确定性行为（build script 输出、env! 宏、include! 生成物等）"
  exit 1
fi
