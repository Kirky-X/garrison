#!/usr/bin/env python3
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
"""解析 rustdoc JSON，输出 garrison 公共 API 面基线。

用法：
    python3 scripts/api_surface.py target/doc/garrison.json > logs/api-surface.txt
    python3 scripts/api_surface.py target/doc/garrison.json --diff logs/api-surface.baseline.txt

输出格式：`<kind>\\t<path>`，按路径排序；`--diff` 额外打印新增/移除项（report-only，退出码 0）。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def collect(doc: dict) -> list[tuple[str, str]]:
    """收集公共项（优先用 paths 的完整路径，缺失时回退到 index 名称）。"""
    index = doc.get("index", {})
    paths = doc.get("paths", {})
    rows: list[tuple[str, str]] = []

    for item_id, meta in paths.items():
        item = index.get(item_id, {})
        visibility = item.get("visibility")
        if visibility is not None and visibility != "public":
            continue
        path = meta.get("path") or []
        if not path or path[0] != "garrison":
            continue
        kind = meta.get("kind") or "unknown"
        rows.append((kind, "::".join(path)))

    if not rows:
        for item in index.values():
            if item.get("visibility") != "public":
                continue
            name = item.get("name")
            if not name:
                continue
            inner = item.get("inner") or {}
            kind = next(iter(inner), "unknown")
            rows.append((kind, name))

    return sorted(set(rows))


def read_baseline(path: Path) -> set[tuple[str, str]]:
    rows: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        kind, _, api_path = line.partition("\t")
        if api_path:
            rows.add((kind, api_path))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="garrison 公共 API 面基线")
    parser.add_argument("json", type=Path, help="rustdoc JSON 路径")
    parser.add_argument("--diff", type=Path, help="基线文件；打印新增/移除项")
    args = parser.parse_args()

    if not args.json.is_file():
        print(f"api-surface: JSON 不存在: {args.json}", file=sys.stderr)
        return 2

    doc = json.loads(args.json.read_text(encoding="utf-8"))
    rows = collect(doc)

    for kind, api_path in rows:
        print(f"{kind}\t{api_path}")
    print(f"# total: {len(rows)}", file=sys.stderr)

    if args.diff:
        if not args.diff.is_file():
            print(f"api-surface: 基线不存在: {args.diff}", file=sys.stderr)
            return 2
        baseline = read_baseline(args.diff)
        current = set(rows)
        added = sorted(current - baseline)
        removed = sorted(baseline - current)
        print(f"# diff vs {args.diff}: +{len(added)} -{len(removed)}", file=sys.stderr)
        for kind, api_path in added:
            print(f"+{kind}\t{api_path}", file=sys.stderr)
        for kind, api_path in removed:
            print(f"-{kind}\t{api_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
