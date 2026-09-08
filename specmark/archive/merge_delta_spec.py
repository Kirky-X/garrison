#!/usr/bin/env bash
# 项目内 specmark 脚本入口（exec 型 wrapper）。
#
# merge_delta_spec.py 为纯参数驱动（--main/--delta/--out/--dry-run 显式路径），
# 不解析自身位置，直接 exec 官方原件即可；本 wrapper 仅统一入口路径，
# 供同目录 archive_change.sh 以 $SCRIPT_DIR/merge_delta_spec.py 引用。
# 合并逻辑全部来自官方原件，本文件不复制、不替代任何判定逻辑。
exec python3 "/home/kirky/.zcode/skills/specmark/scripts/merge_delta_spec.py" "$@"
