#!/usr/bin/env bash
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CITY_URL="https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-City-Test.mmdb"
COUNTRY_URL="https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-Country-Test.mmdb"

echo "下载 GeoLite2-City-Test.mmdb..."
curl -sSL -H "User-Agent: Mozilla/5.0" -o GeoLite2-City-Test.mmdb "$CITY_URL"

echo "下载 GeoLite2-Country-Test.mmdb..."
curl -sSL -H "User-Agent: Mozilla/5.0" -o GeoLite2-Country-Test.mmdb "$COUNTRY_URL"

echo "验证文件大小..."
ls -lh GeoLite2-City-Test.mmdb GeoLite2-Country-Test.mmdb

echo "完成。测试数据文件已保存到 $SCRIPT_DIR/"
