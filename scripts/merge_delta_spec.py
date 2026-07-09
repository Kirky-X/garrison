#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_delta_spec.py — 确定性合并 delta spec 到 main spec.

依据 specmark/references/archive.md Step 4 的合并语义（规则5：确定性逻辑代码化，
不启动 LLM 子 agent）。spec 合并是确定性结构操作，按 R-`<cap>`-NNN 键做
ADD / MODIFY / DELETE / KEEP。

合并语义：
  ADD     R-ID 仅在 delta          → 追加（按数字后缀稳定排序）
  MODIFY  R-ID 同时在 delta 与 main → delta 标题+正文替换 main
  DELETE  delta 标题为 ~~DELETE~~  → 丢弃该 R-ID
  KEEP    R-ID 仅在 main           → 原样保留

Constraints / Out of Scope：精确行并集（main 在前，delta 独有行追加）。幂等：
对同一 (main, delta) 合并两次产生相同字节输出。

用法：
  python3 scripts/merge_delta_spec.py --main specmark/specs/<cap>/spec.md \\
      --delta specmark/changes/<name>/specs/<cap>.md [--dry-run]

退出码：
  0 — 成功（或 dry-run 完成）
  1 — 参数错误 / 文件读取失败
  2 — main 不存在（新能力域）：脚本自动创建 main 为 delta 的副本，返回 0

Copyright (c) 2024-2026 Kirky.X. See LICENSE for full license text.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# R-ID 匹配：### R-<prefix>-NNN: <title>
# prefix 由小写字母/数字/连字符组成，NNN 为数字。
# 示例：R-error-001 / R-annotation-macros-002 / R-ac-010
R_ID_RE = re.compile(r"^###\s+(R-[a-z0-9]+(?:-[a-z0-9]+)*-\d+)\s*:\s*(.*)$")

# 从 R-ID 提取数字后缀用于稳定排序
R_ID_NUM_RE = re.compile(r"-(\d+)$")

# DELETE 标记：delta 标题文本为 ~~DELETE~~
DELETE_MARKER = "~~DELETE~~"

# 三个 section header
SEC_REQUIREMENTS = "## Requirements"
SEC_CONSTRAINTS = "## Constraints"
SEC_OUT_OF_SCOPE = "## Out of Scope"


@dataclass
class Requirement:
    """单个 R-<cap>-NNN 需求条目。"""

    r_id: str  # 如 "R-error-001"
    title: str  # 标题文本（不含 R-ID 前缀）
    body: str  # 正文（含末尾换行，不含 ### header 行）


@dataclass
class ParsedSpec:
    """解析后的 spec 文件结构。"""

    header: str  # 文件开头到 ## Requirements 之前的所有内容（含 # Spec — xxx 标题和 > 引用块）
    requirements: Dict[str, Requirement] = field(default_factory=dict)
    req_order: List[str] = field(default_factory=list)  # 原始出现顺序
    constraints: List[str] = field(default_factory=list)  # Constraints section 的行（不含 ## header）
    out_of_scope: List[str] = field(default_factory=list)  # Out of Scope section 的行（不含 ## header）


def parse_spec(text: str) -> ParsedSpec:
    """解析 spec markdown 文本为 ParsedSpec 结构。

    结构约定：
      # Spec — <name>
      > Delta spec for change ...
      <任意 header 内容>
      ## Requirements
      ### R-xxx-001: title
      <body>
      ### R-xxx-002: title
      <body>
      ## Constraints
      <lines>
      ## Out of Scope
      <lines>
    """
    lines = text.split("\n")
    parsed = ParsedSpec(header="")

    # Phase 1: 找到 ## Requirements 的位置，切出 header
    req_start: Optional[int] = None
    for i, line in enumerate(lines):
        if line.strip() == SEC_REQUIREMENTS:
            req_start = i
            break

    if req_start is None:
        # 没有 ## Requirements section，整个文件作为 header
        parsed.header = text
        return parsed

    # header 包含到 ## Requirements 行之前的内容（不含该行）
    parsed.header = "\n".join(lines[:req_start])

    # Phase 2: 从 req_start+1 开始解析 sections
    current_section: Optional[str] = SEC_REQUIREMENTS
    current_req: Optional[Requirement] = None
    current_body_lines: List[str] = []

    def _flush_req() -> None:
        nonlocal current_req, current_body_lines
        if current_req is not None:
            current_req.body = "\n".join(current_body_lines)
            parsed.requirements[current_req.r_id] = current_req
            parsed.req_order.append(current_req.r_id)
            current_req = None
            current_body_lines = []

    for line in lines[req_start + 1 :]:
        stripped = line.strip()

        # 检测 section 切换
        if stripped == SEC_CONSTRAINTS:
            _flush_req()
            current_section = SEC_CONSTRAINTS
            continue
        elif stripped == SEC_OUT_OF_SCOPE:
            _flush_req()
            current_section = SEC_OUT_OF_SCOPE
            continue
        elif stripped.startswith("## ") and stripped not in (
            SEC_REQUIREMENTS,
            SEC_CONSTRAINTS,
            SEC_OUT_OF_SCOPE,
        ):
            # 未知 section header，刷新当前 req 并跳过（不解析）
            _flush_req()
            current_section = None
            continue

        if current_section == SEC_REQUIREMENTS:
            # 检测 R-ID header
            match = R_ID_RE.match(line)
            if match:
                _flush_req()
                r_id = match.group(1)
                title = match.group(2).strip()
                current_req = Requirement(r_id=r_id, title=title, body="")
                current_body_lines = []
            else:
                if current_req is not None:
                    current_body_lines.append(line)
                # else: Requirements section 内但 R-ID header 之前的行（如空行），忽略
        elif current_section == SEC_CONSTRAINTS:
            parsed.constraints.append(line)
        elif current_section == SEC_OUT_OF_SCOPE:
            parsed.out_of_scope.append(line)
        # current_section is None: 未知 section 的行，跳过

    _flush_req()
    return parsed


def _r_id_sort_key(r_id: str) -> Tuple[str, int]:
    """R-ID 排序键：(prefix, numeric_suffix)。

    如 R-error-001 → ("R-error", 1)，R-error-010 → ("R-error", 10)。
    同 prefix 内按数字升序；跨 prefix 按字典序。
    """
    match = R_ID_NUM_RE.search(r_id)
    if match:
        num = int(match.group(1))
        prefix = r_id[: match.start()]
        return (prefix, num)
    return (r_id, 0)


def _merge_lines(main_lines: List[str], delta_lines: List[str]) -> List[str]:
    """精确行并集合并：main 在前，delta 独有行追加。幂等。

    空行保留（不 strip 比较，按原样比较）。但尾部空行会被 trim。
    """
    merged = list(main_lines)
    main_set = set(main_lines)
    for line in delta_lines:
        if line not in main_set:
            merged.append(line)
            main_set.add(line)
    # 移除尾部连续空行，保留最多一个
    while len(merged) > 1 and merged[-1] == "" and merged[-2] == "":
        merged.pop()
    return merged


@dataclass
class MergeReport:
    """合并结果摘要。"""

    add: List[str] = field(default_factory=list)
    modify: List[str] = field(default_factory=list)
    delete: List[str] = field(default_factory=list)
    keep: List[str] = field(default_factory=list)
    constraints_main: int = 0
    constraints_delta_unique: int = 0
    out_of_scope_main: int = 0
    out_of_scope_delta_unique: int = 0
    new_capability: bool = False


def merge(main: Optional[ParsedSpec], delta: ParsedSpec) -> Tuple[ParsedSpec, MergeReport]:
    """合并 main 和 delta，返回 (merged_spec, report)。

    若 main 为 None（新能力域），delta 直接作为新 main。
    """
    report = MergeReport()

    if main is None:
        # 新能力域：delta 即新 main
        report.new_capability = True
        for r_id in delta.req_order:
            report.add.append(r_id)
        return delta, report

    # --- 合并 Requirements ---
    merged_reqs: Dict[str, Requirement] = {}
    merged_order: List[str] = []

    # KEEP: R-ID 仅在 main
    for r_id in main.req_order:
        if r_id not in delta.requirements:
            merged_reqs[r_id] = main.requirements[r_id]
            merged_order.append(r_id)
            report.keep.append(r_id)

    # ADD / MODIFY / DELETE: 遍历 delta
    for r_id in delta.req_order:
        delta_req = delta.requirements[r_id]
        if delta_req.title.strip() == DELETE_MARKER:
            # DELETE: 丢弃该 R-ID（不加入 merged）
            report.delete.append(r_id)
            # 若该 R-ID 在 main 中存在，从 merged 中移除（如果之前 KEEP 加入了）
            merged_reqs.pop(r_id, None)
            if r_id in merged_order:
                merged_order.remove(r_id)
                if r_id in report.keep:
                    report.keep.remove(r_id)
        else:
            if r_id in main.requirements:
                # MODIFY: delta 替换 main
                report.modify.append(r_id)
                # 若之前 KEEP 加入了，先移除
                if r_id in merged_reqs:
                    del merged_reqs[r_id]
                    if r_id in merged_order:
                        merged_order.remove(r_id)
                    if r_id in report.keep:
                        report.keep.remove(r_id)
            else:
                # ADD: 新增
                report.add.append(r_id)
            merged_reqs[r_id] = delta_req
            merged_order.append(r_id)

    # 按 (prefix, number) 稳定排序
    merged_order.sort(key=_r_id_sort_key)

    # --- 合并 Constraints ---
    merged_constraints = _merge_lines(main.constraints, delta.constraints)
    report.constraints_main = len(main.constraints)
    report.constraints_delta_unique = len(merged_constraints) - len(main.constraints)

    # --- 合并 Out of Scope ---
    merged_out_of_scope = _merge_lines(main.out_of_scope, delta.out_of_scope)
    report.out_of_scope_main = len(main.out_of_scope)
    report.out_of_scope_delta_unique = len(merged_out_of_scope) - len(main.out_of_scope)

    merged = ParsedSpec(
        header=main.header,  # 保留 main 的 header（含 # Spec — xxx 标题）
        requirements=merged_reqs,
        req_order=merged_order,
        constraints=merged_constraints,
        out_of_scope=merged_out_of_scope,
    )
    return merged, report


def reconstruct(parsed: ParsedSpec) -> str:
    """将 ParsedSpec 重建为 markdown 文本。"""
    parts: List[str] = [parsed.header.rstrip(), ""]

    # ## Requirements section
    parts.append(SEC_REQUIREMENTS)
    parts.append("")
    for r_id in parsed.req_order:
        req = parsed.requirements[r_id]
        parts.append(f"### {req.r_id}: {req.title}")
        if req.body:
            # body 已含换行，直接追加；确保以空行分隔下一个条目
            body = req.body.rstrip()
            parts.append(body)
        parts.append("")

    # ## Constraints section
    if parsed.constraints:
        parts.append(SEC_CONSTRAINTS)
        parts.append("")
        for line in parsed.constraints:
            parts.append(line)
        # 确保尾部有空行分隔
        if parts and parts[-1] != "":
            parts.append("")

    # ## Out of Scope section
    if parsed.out_of_scope:
        parts.append(SEC_OUT_OF_SCOPE)
        parts.append("")
        for line in parsed.out_of_scope:
            parts.append(line)
        if parts and parts[-1] != "":
            parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def format_report(report: MergeReport, main_path: Path, delta_path: Path, main_exists: bool) -> str:
    """格式化 dry-run 摘要。"""
    lines = [
        "=== merge_delta_spec.py DRY RUN ===",
        f"main:  {main_path} ({'exists' if main_exists else 'NOT FOUND (new capability)'})",
        f"delta: {delta_path}",
        "",
    ]

    if report.new_capability:
        lines.append(f"NEW CAPABILITY: delta becomes new main ({len(report.add)} requirements)")
        lines.append("")
        for r_id in report.add:
            lines.append(f"  ADD:   {r_id}")
        return "\n".join(lines)

    lines.append("Requirements:")
    if not (report.add or report.modify or report.delete or report.keep):
        lines.append("  (no changes)")
    for r_id in report.keep:
        lines.append(f"  KEEP:   {r_id}")
    for r_id in report.modify:
        lines.append(f"  MODIFY: {r_id}")
    for r_id in report.add:
        lines.append(f"  ADD:    {r_id}")
    for r_id in report.delete:
        lines.append(f"  DELETE: {r_id}")

    lines.append("")
    lines.append(
        f"Constraints: {report.constraints_main} main + {report.constraints_delta_unique} delta-unique"
        f" = {report.constraints_main + report.constraints_delta_unique} merged"
    )
    lines.append(
        f"Out of Scope: {report.out_of_scope_main} main + {report.out_of_scope_delta_unique} delta-unique"
        f" = {report.out_of_scope_main + report.out_of_scope_delta_unique} merged"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="确定性合并 delta spec 到 main spec（specmark archive --sync）"
    )
    parser.add_argument("--main", required=True, type=Path, help="main spec 路径（specmark/specs/<cap>/spec.md）")
    parser.add_argument("--delta", required=True, type=Path, help="delta spec 路径")
    parser.add_argument("--dry-run", action="store_true", help="仅预览合并结果，不写入文件")
    args = parser.parse_args()

    # 读取 delta（必须存在）
    if not args.delta.is_file():
        print(f"ERROR: delta spec 不存在: {args.delta}", file=sys.stderr)
        return 1
    delta_text = args.delta.read_text(encoding="utf-8")
    delta_parsed = parse_spec(delta_text)

    # 读取 main（可能不存在 = 新能力域）
    main_exists = args.main.is_file()
    main_parsed: Optional[ParsedSpec] = None
    if main_exists:
        main_parsed = parse_spec(args.main.read_text(encoding="utf-8"))

    # 合并
    merged, report = merge(main_parsed, delta_parsed)

    # 输出
    if args.dry_run:
        print(format_report(report, args.main, args.delta, main_exists))
        print("")
        print("--- merged preview (first 80 lines) ---")
        merged_text = reconstruct(merged)
        for line in merged_text.split("\n")[:80]:
            print(line)
        total_lines = len(merged_text.split("\n"))
        if total_lines > 80:
            print(f"... ({total_lines - 80} more lines)")
        return 0

    # 实际写入
    merged_text = reconstruct(merged)
    args.main.parent.mkdir(parents=True, exist_ok=True)
    args.main.write_text(merged_text, encoding="utf-8")

    # 一行摘要
    if report.new_capability:
        print(f"[merge] NEW CAPABILITY {args.main.parent.name}: {len(report.add)} requirements added")
    else:
        print(
            f"[merge] {args.main.parent.name}: "
            f"+{len(report.add)} ADD, {len(report.modify)} MODIFY, "
            f"-{len(report.delete)} DELETE, {len(report.keep)} KEEP"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
