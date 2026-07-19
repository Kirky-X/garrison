#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X. All rights reserved.
# See LICENSE for full license text.
#
# Release 工作流本地预检查脚本
# 用法：
#   ./scripts/release.sh precheck              # 完整预检查（所有检查项）
#   ./scripts/release.sh check-version <ver>   # 检查版本一致性（Cargo.toml == CHANGELOG == tag）
#   ./scripts/release.sh gen-changelog <range> [version]  # 从 git log 生成 changelog 段落
#   ./scripts/release.sh bump-version <ver>    # bump Cargo.toml 版本号
#
# 退出码：
#   0 = 所有检查通过
#   1 = 检查失败（见错误输出）
#   2 = 用法错误

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# 项目根目录（脚本所在目录的父目录）
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# semver 格式校验（防注入）：x.y.z 或 x.y.z-rc.N 等
validate_semver() {
    local version="$1"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        fail "非法版本号格式: $version（期望 x.y.z 或 x.y.z-rc.N）"
        return 1
    fi
    return 0
}

# ==============================================================================
# 子命令：check-version <version>
# 检查 Cargo.toml / CHANGELOG.md / git tag 三者版本一致
# ==============================================================================
cmd_check_version() {
    local version="${1:-}"
    if [[ -z "$version" ]]; then
        fail "用法: $0 check-version <version>  (e.g. 0.7.1)"
        exit 2
    fi
    validate_semver "$version" || exit 2

    info "检查版本一致性: $version"

    # 1. 检查 Cargo.toml version 字段
    local cargo_version
    cargo_version=$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)".*/\1/')
    if [[ "$cargo_version" != "$version" ]]; then
        fail "Cargo.toml version = \"$cargo_version\", 期望 \"$version\""
        exit 1
    fi
    ok "Cargo.toml version: $cargo_version"

    # 2. 检查 CHANGELOG.md 是否有对应章节
    if ! grep -qE "^## \[${version}\] " CHANGELOG.md; then
        fail "CHANGELOG.md 缺少 \"## [$version] - YYYY-MM-DD\" 章节"
        exit 1
    fi
    ok "CHANGELOG.md: 找到 ## [$version] 章节"

    # 3. 检查 git tag 是否已存在（应当不存在，发布前检查）
    # 重复发布属于错误状态，必须显性失败（规则 12）
    if git rev-parse -q --verify "refs/tags/v${version}" >/dev/null; then
        fail "git tag v${version} 已存在（如需重新发布需先删除 tag 并 cargo yank）"
        exit 1
    fi
    ok "git tag v${version} 不存在（待发布）"

    ok "版本一致性检查通过"
}

# ==============================================================================
# 子命令：gen-changelog <git-range> [version]
# 从 git log 生成 changelog 段落（仅 oneline，需人工分类）
# version 缺省时为 "Unreleased"，发布时应显式传入版本号
# ==============================================================================
cmd_gen_changelog() {
    local range="${1:-}"
    local version="${2:-unreleased}"
    if [[ -z "$range" ]]; then
        fail "用法: $0 gen-changelog <git-range> [version]  (e.g. v0.7.0..HEAD 0.7.1)"
        exit 2
    fi
    if [[ "$version" != "unreleased" ]]; then
        validate_semver "$version" || exit 2
    fi

    info "生成 changelog（range: $range, version: $version）"
    echo
    if [[ "$version" == "unreleased" ]]; then
        echo "## [Unreleased] - $(date +%Y-%m-%d)"
    else
        echo "## [${version}] - $(date +%Y-%m-%d)"
    fi
    echo
    echo "### Changed"
    echo
    git log --oneline --no-decorate "$range" | while IFS= read -r line; do
        printf -- '- %s\n' "$line"
    done
    echo
    info "注意：以上为 git log oneline 自动生成，需人工分类到 Added/Changed/Fixed/Security 章节"
}

# ==============================================================================
# 子命令：bump-version <new-version>
# 修改 Cargo.toml version 字段
# ==============================================================================
cmd_bump_version() {
    local new_version="${1:-}"
    if [[ -z "$new_version" ]]; then
        fail "用法: $0 bump-version <new-version>  (e.g. 0.7.1)"
        exit 2
    fi
    validate_semver "$new_version" || exit 2

    local old_version
    old_version=$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)".*/\1/')
    info "bump version: $old_version → $new_version"

    # 使用 sed 原地替换第一个 version = "..." 行
    # new_version 已通过 validate_semver 校验，不含 sed 特殊字符
    sed -i -E "0,/^version = \".+\"/s//version = \"$new_version\"/" Cargo.toml

    # 验证
    local actual_version
    actual_version=$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)".*/\1/')
    if [[ "$actual_version" != "$new_version" ]]; then
        fail "bump 失败：实际 version = \"$actual_version\""
        exit 1
    fi
    ok "Cargo.toml version 已更新为 $new_version"
}

# ==============================================================================
# 子命令：precheck
# 完整预检查（所有检查项）
# 顺序与 RELEASING.md 流程图一致：fmt → SAST → test → doc → clippy → version
# ==============================================================================
cmd_precheck() {
    info "=== Bulwark Release 预检查 ==="
    echo

    local failures=0

    # 1. cargo fmt --check（轻量，先跑快速失败）
    info "[1/8] cargo fmt --check"
    if cargo fmt --all -- --check >/dev/null 2>&1; then
        ok "fmt 通过"
    else
        fail "fmt 失败（运行 cargo fmt --all 修复）"
        failures=$((failures + 1))
    fi

    # 2. cargo audit（SAST 安全审查，规则 19 强制要求 0 CRITICAL）
    info "[2/8] cargo audit"
    if ! command -v cargo-audit >/dev/null 2>&1; then
        fail "cargo-audit 未安装，无法执行安全审查（运行 cargo install cargo-audit 安装）"
        failures=$((failures + 1))
    elif cargo audit >/dev/null 2>&1; then
        ok "cargo audit 通过（0 CRITICAL）"
    else
        fail "cargo audit 发现漏洞"
        failures=$((failures + 1))
    fi

    # 3. cargo deny check（依赖审计，规则 18 强制要求）
    info "[3/8] cargo deny check"
    if ! command -v cargo-deny >/dev/null 2>&1; then
        fail "cargo-deny 未安装，无法执行依赖审计（运行 cargo install cargo-deny 安装）"
        failures=$((failures + 1))
    elif cargo deny check >/dev/null 2>&1; then
        ok "cargo deny 通过"
    else
        fail "cargo deny 失败"
        failures=$((failures + 1))
    fi

    # 4. cargo test --lib（核心测试）
    info "[4/8] cargo test --features full --lib"
    if cargo test --features full --lib >/dev/null 2>&1; then
        ok "lib 测试通过"
    else
        fail "lib 测试失败"
        failures=$((failures + 1))
    fi

    # 5. cargo test --test '*'（E2E 测试）
    info "[5/8] cargo test --features full --test '*'"
    if cargo test --features full --test '*' --no-fail-fast >/dev/null 2>&1; then
        ok "E2E 测试通过"
    else
        fail "E2E 测试失败"
        failures=$((failures + 1))
    fi

    # 6. cargo doc（零警告）
    info "[6/8] cargo doc --features full --no-deps"
    local doc_output
    doc_output=$(RUSTDOCFLAGS="-D warnings" cargo doc --features full --no-deps 2>&1 || true)
    if [[ -z "$doc_output" ]]; then
        ok "cargo doc 零警告"
    else
        fail "cargo doc 有警告/错误："
        echo "$doc_output" | head -20 | sed 's/^/    /'
        failures=$((failures + 1))
    fi

    # 7. cargo clippy -D warnings（重量级，最后跑）
    info "[7/8] cargo clippy --features full --lib --tests -- -D warnings"
    if cargo clippy --features full --lib --tests -- -D warnings >/dev/null 2>&1; then
        ok "clippy 通过"
    else
        fail "clippy 失败（0 warnings 要求）"
        failures=$((failures + 1))
    fi

    # 8. 版本一致性
    info "[8/8] 版本一致性检查"
    local cargo_version
    cargo_version=$(grep -E '^version = ' Cargo.toml | head -1 | sed -E 's/version = "([^"]+)".*/\1/')
    if ! validate_semver "$cargo_version"; then
        fail "Cargo.toml 版本号格式非法: $cargo_version"
        failures=$((failures + 1))
    elif grep -qE "^## \[${cargo_version}\] " CHANGELOG.md; then
        ok "CHANGELOG.md 包含 ## [$cargo_version] 章节"
    else
        fail "CHANGELOG.md 缺少 ## [$cargo_version] 章节"
        failures=$((failures + 1))
    fi

    echo
    if [[ $failures -eq 0 ]]; then
        ok "=== 预检查全部通过 ==="
        info "可以执行: git tag -a v${cargo_version} -m \"Release v${cargo_version}\" && git push origin v${cargo_version}"
        exit 0
    else
        fail "=== 预检查失败：$failures 项 ==="
        exit 1
    fi
}

# ==============================================================================
# 主入口
# ==============================================================================
main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        precheck)       cmd_precheck "$@" ;;
        check-version)  cmd_check_version "$@" ;;
        gen-changelog)  cmd_gen_changelog "$@" ;;
        bump-version)   cmd_bump_version "$@" ;;
        ""|-h|--help|help)
            cat <<EOF
Bulwark Release 工作流本地预检查脚本

用法:
  $0 precheck                  完整预检查（所有检查项）
  $0 check-version <version>   检查版本一致性（Cargo.toml == CHANGELOG == tag）
  $0 gen-changelog <range> [version]  从 git log 生成 changelog 段落
  $0 bump-version <version>    bump Cargo.toml 版本号

示例:
  $0 precheck
  $0 check-version 0.7.1
  $0 gen-changelog v0.7.0..HEAD 0.7.1
  $0 bump-version 0.7.1

详见 docs/RELEASING.md
EOF
            ;;
        *)
            fail "未知子命令: $cmd"
            echo "运行 $0 --help 查看用法"
            exit 2
            ;;
    esac
}

main "$@"
