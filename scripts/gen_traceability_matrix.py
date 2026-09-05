#!/usr/bin/env python3
# Copyright (c) 2026 Kirky.X. All rights reserved.
# See LICENSE for full license text.
# -*- coding: utf-8 -*-
"""
gen_traceability_matrix.py — 生成集中式需求追溯矩阵（RTM）。

追溯链：specmark/specs/<capability>/spec.md 的 R-<cap>-NNN 需求
       ↔ tests/ 与 src/ 中以注释形式引用该 R-ID 的测试/实现位置。
另覆盖 FRD §8.1 的 BW-AC-001~015 验收标准（验收标准 ID 直接在测试注释中引用）。

用法：python3 scripts/gen_traceability_matrix.py [--output docs/traceability-matrix.md]

退出码：0 — 成功；1 — specmark/specs 缺失。

统计口径：
  covered   — 至少 1 个 .rs 文件引用该 R-ID（注释/文档/测试名）
  uncovered — 无任何 .rs 引用（仅代表「无静态引用」，不代表无测试，
               作为人工复核清单输出，见矩阵末尾 Gap 清单）
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = PROJECT_ROOT / "specmark" / "specs"
SCAN_DIRS = [PROJECT_ROOT / "tests", PROJECT_ROOT / "src"]

# spec 主条目：### R-<cap>-NNN: <title>
R_ID_RE = re.compile(r"^###\s+(R-[a-z0-9]+(?:-[a-z0-9]+)*-\d+)\s*:\s*(.*)$", re.M)
# BW-AC 验收标准（FRD §8.1，经 specmark/specs/acceptance-criteria 锚定到测试）
BW_AC_RE = re.compile(r"BW-AC-\d{3}")

# 源文件中的引用索引：ID → {文件相对路径, ...}
ref_index: dict[str, set[str]] = defaultdict(set)
# 文件全文索引（能力级关键词启发式用）：相对路径 → 全文小写
file_texts: dict[str, str] = {}


def build_reference_index() -> None:
    """一次扫描 tests/ 与 src/ 的 .rs 文件，建立 R-ID / BW-AC 引用索引。"""
    for base in SCAN_DIRS:
        for rs in base.rglob("*.rs"):
            rel = rs.relative_to(PROJECT_ROOT).as_posix()
            try:
                text = rs.read_text(encoding="utf-8")
            except OSError:
                continue
            file_texts[rel] = text.lower()
            for m in R_ID_RE.finditer(text):
                ref_index[m.group(1)].add(rel)
            for m in BW_AC_RE.finditer(text):
                ref_index[m.group(0)].add(rel)


def parse_specs() -> list[tuple[str, list[tuple[str, str]]]]:
    """解析 specmark/specs/*/spec.md，返回 [(capability, [(rid, title), ...])]。"""
    out = []
    for cap_dir in sorted(SPECS_DIR.iterdir()):
        spec = cap_dir / "spec.md"
        if not spec.is_file():
            continue
        rids = [(m.group(1), m.group(2).strip()) for m in R_ID_RE.finditer(spec.read_text(encoding="utf-8"))]
        if rids:
            out.append((cap_dir.name, rids))
    return out


def capability_keyword_hits(cap: str) -> list[str]:
    """能力级启发式：能力名的 token 组合在 .rs 文件名/内容中的命中（小写包含）。

    如 `tenant-isolation` → 依次尝试 `tenant_isolation`、`tenant-isolation`、`tenantisolation`、
    `tenant`。返回命中的文件相对路径（按测试目录优先排序），最多 8 个。
    """
    tokens = [t for t in re.split(r"[-_]", cap) if t]
    candidates = []
    joined = "".join(tokens)
    if len(tokens) > 1:
        candidates += ["_".join(tokens), "-".join(tokens), joined]
    if len(tokens) == 1 or len(tokens[0]) >= 4:
        candidates.append(tokens[0])
    for kw in candidates:
        hits = [
            rel
            for rel, text in sorted(file_texts.items(), key=lambda x: (not x[0].startswith("tests/"), x[0]))
            if kw in rel.lower() or kw in text
        ]
        if hits:
            return hits[:8]
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="docs/traceability-matrix.md")
    args = ap.parse_args()

    if not SPECS_DIR.is_dir():
        print("[rtm] specmark/specs 不存在", file=sys.stderr)
        return 1

    build_reference_index()
    specs = parse_specs()

    total = covered = 0
    gaps: list[str] = []
    lines = [
        "# Garrison 需求追溯矩阵（RTM）",
        "",
        "> 本文件由 `scripts/gen_traceability_matrix.py` 自动生成，请勿手改。",
        "> 追溯链：`specmark/specs/<capability>/spec.md` 的 `R-<cap>-NNN` ↔ `tests/`、`src/` 中的静态引用；",
        "> BW-AC-001~015 为 FRD §8.1 验收标准（需求基线 `docs/origin/`）。",
        "> 「uncovered」仅表示无静态 ID 引用，需人工复核是否存在等价测试。",
        "",
    ]

    for cap, rids in specs:
        hits = capability_keyword_hits(cap)
        lines.append(f"## {cap}")
        lines.append("")
        if hits:
            lines.append(
                f"> 关键词启发式：能力名在 {len(hits)} 个源文件命中（test 优先）→ {', '.join(f'`{h}`' for h in hits[:4])}…"
            )
            lines.append("")
        lines.append("| 需求 ID | 标题 | 状态 | 引用位置 |")
        lines.append("|---|---|---|---|")
        for rid, title in rids:
            total += 1
            refs = sorted(ref_index.get(rid, ()))
            if refs:
                covered += 1
                status = "covered"
            else:
                gaps.append(rid)
                status = "uncovered"
            ref_str = "<br>".join(f"`{r}`" for r in refs) if refs else "—"
            lines.append(f"| `{rid}` | {title} | {status} | {ref_str} |")
        lines.append("")

    bw_ids = sorted({m for m in ref_index if m.startswith("BW-AC-")})
    lines.append("## BW-AC 验收标准（FRD §8.1）")
    lines.append("")
    lines.append("| 验收标准 | 状态 | 测试位置 |")
    lines.append("|---|---|---|")
    for i in range(1, 16):
        bw = f"BW-AC-{i:03d}"
        refs = sorted(ref_index.get(bw, ()))
        status = "covered" if refs else "uncovered"
        if refs:
            covered += 1
        else:
            gaps.append(bw)
        total += 1
        ref_str = "<br>".join(f"`{r}`" for r in refs) if refs else "—"
        lines.append(f"| `{bw}` | {status} | {ref_str} |")
    lines.append("")

    lines += [
        "## 统计",
        "",
        f"- 规格需求条目：{total}（specmark specs {total - len(bw_ids)} + BW-AC {len(bw_ids)}）",
        f"- 有静态引用（covered）：{covered}（{covered / total * 100:.1f}%）",
        f"- 无静态引用（uncovered，待人工复核）：{len(gaps)}",
        "",
    ]
    if gaps:
        lines.append("### Gap 清单")
        lines.append("")
        lines += [f"- `{g}`" for g in gaps]
        lines.append("")

    out_path = PROJECT_ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[rtm] 已生成 {out_path}：{covered}/{total} 有静态引用，{len(gaps)} 个待复核")
    return 0


if __name__ == "__main__":
    sys.exit(main())
