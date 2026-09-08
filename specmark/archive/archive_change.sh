#!/usr/bin/env bash
# 项目内 specmark 脚本入口（source 型 wrapper）。
#
# 官方 archive_change.sh 通过 `readlink -f "$0"` 定位项目根（ROOT=SCRIPT_DIR/..，
# CHANGE_DIR=$ROOT/specmark/changes）。官方原件安装于 skill 目录，直接调用
# （或经软/硬链接调用）时 readlink -f 解析回 skill 路径，specmark 目录定位错误。
# 此处以本项目路径为 $0 source 官方原件，使 ROOT 正确解析到项目根。
# 官方原件含 CRLF 行尾（bash 报 $'\r': command not found），source 前经 tr 剥离。
# 判定逻辑全部来自官方原件，本文件不复制、不替代任何判定逻辑。
# 注意：官方原件以 $SCRIPT_DIR/merge_delta_spec.py 调用合并器，
# 故本目录需存在 merge_delta_spec.py（见同目录同名 exec 型 wrapper）。

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source <(tr -d '\r' < "/home/kirky/.zcode/skills/specmark/scripts/archive_change.sh") "$@"
