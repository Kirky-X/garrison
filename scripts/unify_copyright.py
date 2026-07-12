#!/usr/bin/env python3
"""
Unify copyright headers across all code files in the project.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

COMMENT_STYLES: dict[str, str] = {
    ".rs": "//! ",
    ".sql": "-- ",
    ".toml": "# ",
    ".yaml": "# ",
    ".yml": "# ",
    ".sh": "# ",
    ".py": "# ",
}

LINE1_TEXT = "Copyright (c) 2026 Kirky.X. All rights reserved."
LINE2_TEXT = "See LICENSE for full license text."


def prefix(ext: str) -> str:
    return COMMENT_STYLES.get(ext, "# ")


def header_lines(ext: str) -> list[str]:
    p = prefix(ext)
    return [f"{p}{LINE1_TEXT}\n", f"{p}{LINE2_TEXT}\n"]


def is_blank_comment(line: str, p: str) -> bool:
    s = line.rstrip()
    return s == p.rstrip() or s == ""


def has_copyright_at_top(lines: list[str], ext: str) -> bool:
    if len(lines) < 2:
        return False
    return LINE1_TEXT in lines[0] and LINE2_TEXT in lines[1]


def remove_copyright(lines: list[str], ext: str) -> tuple[list[str], bool]:
    p = prefix(ext)
    found = False
    idx_c1: list[int] = []
    idx_c2: list[int] = []

    for i, line in enumerate(lines):
        if not found and LINE1_TEXT in line:
            idx_c1.append(i)
            found = True
        if LINE2_TEXT in line:
            idx_c2.append(i)

    if not found:
        return lines, False

    remove: set[int] = set()
    for idx in idx_c1 + idx_c2:
        remove.add(idx)
        if idx > 0 and is_blank_comment(lines[idx - 1], p):
            remove.add(idx - 1)
        if idx < len(lines) - 1 and is_blank_comment(lines[idx + 1], p):
            remove.add(idx + 1)

    result = [l for i, l in enumerate(lines) if i not in remove]
    return result, True


def dedup_blank_comments(lines: list[str], p: str) -> list[str]:
    out: list[str] = []
    prev_blank = False
    for line in lines:
        blank = is_blank_comment(line, p)
        if blank and prev_blank:
            continue
        prev_blank = blank
        out.append(line)
    return out


def process_file(filepath: Path) -> bool:
    ext = filepath.suffix.lower()
    if ext not in COMMENT_STYLES:
        return False

    if filepath.name == "unify_copyright.py":
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if has_copyright_at_top(lines, ext):
        return False

    p = prefix(ext)
    new_lines, _ = remove_copyright(lines, ext)
    new_lines = dedup_blank_comments(new_lines, p)

    while new_lines and new_lines[0].strip() == "":
        new_lines.pop(0)

    header = header_lines(ext)
    header.append("\n")
    result = header + new_lines

    if result and not result[-1].endswith("\n"):
        result[-1] += "\n"

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(result)
    return True


def find_files() -> list[Path]:
    exclude = {
        ".git", "target", ".venv", ".gitnexus",
        "temp", "coverage", "coverage_report", ".trae", ".agents",
    }
    files: list[Path] = []
    for root, dirs, names in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in exclude]
        for name in names:
            ext = os.path.splitext(name)[1].lower()
            if ext in COMMENT_STYLES:
                files.append(Path(root) / name)
    return files


def main() -> int:
    files = find_files()
    modified: list[Path] = []
    skipped: list[Path] = []

    for fp in sorted(files):
        try:
            if process_file(fp):
                modified.append(fp)
            else:
                skipped.append(fp)
        except Exception as e:
            print(f"ERROR: {fp}: {e}", file=sys.stderr)

    print(f"Total:   {len(files)}")
    print(f"Changed: {len(modified)}")
    print(f"OK:      {len(skipped)}")
    if modified:
        print("\nModified:")
        for fp in modified:
            print(f"  {fp.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
