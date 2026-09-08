#!/usr/bin/env bash
# 项目内 specmark 脚本入口（source 型 wrapper）。
#
# 官方 check_phase.sh 通过 `readlink -f "$0"` 定位项目根（ROOT=SCRIPT_DIR/..，
# CHANGE_DIR=$ROOT/specmark/changes）。官方原件安装于 skill 目录，直接调用
# （或经软/硬链接调用）时 readlink -f 解析回 skill 路径，change 目录定位错误。
# 此处以本项目路径为 $0 source 官方原件，使 ROOT 正确解析到项目根。
# 判定逻辑全部来自官方原件，本文件不复制、不替代任何判定逻辑。

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "/home/kirky/.zcode/skills/specmark/scripts/check_phase.sh" "$@"
