#!/usr/bin/env python3
# Copyright (c) 2026 Kirky.X. All rights reserved.
# See LICENSE for full license text.

"""T052: E2E 测试日志聚合分析器（一键报告生成）。

扫描 `logs/` 目录下的 `e2e_http.jsonl` / `perf.jsonl` / `pentest_report.json`，
聚合输出 `logs/e2e_final_report.md`，含 4 节：

  1. HTTP 交互统计（总请求 / 状态码分布 / P50/P95/P99）
  2. 性能基线对照表（实际 vs 目标 P99<200ms/1000RPS/0.1%）
  3. 渗透测试矩阵（7 类攻击 × N payload 表格）
  4. 异常请求列表（5xx / 超时 / 响应体 >4KB）

依赖：仅 Python 标准库（argparse + json + collections + pathlib）。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# 性能基线目标（与 tests/e2e/perf.rs 中断言保持一致）
# (endpoint, target_p99_ms, target_rps, target_error_rate_pct)
PERF_TARGETS = [
    ("perf_login_p99_under_200ms_1000rps", "/api/v1/auth/login", 200, 1000, 0.1),
    (
        "perf_check_login_p99_under_50ms_5000rps",
        "/api/v1/auth/check-login",
        50,
        5000,
        0.1,
    ),
    (
        "perf_check_permission_p99_under_50ms_5000rps",
        "/api/v1/auth/check-permission",
        50,
        5000,
        0.1,
    ),
]

# 7 类攻击矩阵（与 tests/e2e/pentest/ 子模块对应）
ATTACK_TYPES = [
    "sql_injection",
    "xss",
    "csrf",
    "auth_bypass",
    "privilege_escalation",
    "session_hijack",
    "brute_force",
]

OVERSIZE_THRESHOLD = 4 * 1024  # 4KB


def percentile(sorted_values: list[int], k: int) -> int:
    """Nearest-rank 百分位计算（与 Rust 端 perf.rs 一致）。"""
    n = len(sorted_values)
    if n == 0:
        return 0
    idx = min(n * k // 100, n - 1)
    return sorted_values[idx]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """逐行读取 JSONL 文件，跳过空行和解析失败行。"""
    if not path.exists():
        return []
    results: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def resp_body_size(resp_body: Any) -> int:
    """计算 resp_body 字段的字节数（与 Rust 端 resp_body_size 一致）。"""
    if resp_body is None:
        return 0
    if isinstance(resp_body, str):
        return len(resp_body.encode("utf-8"))
    return len(json.dumps(resp_body, ensure_ascii=False).encode("utf-8"))


def section_http_interactions(http_entries: list[dict[str, Any]]) -> str:
    """生成第 1 节：HTTP 交互统计。"""
    lines: list[str] = ["## 1. HTTP 交互统计", ""]
    if not http_entries:
        lines.extend(["- 总请求数: 0", "- 状态码分布: 无数据", "- P50/P95/P99: 无数据"])
        lines.append("")
        return "\n".join(lines)

    total = len(http_entries)
    status_counter: Counter[str] = Counter()
    latencies: list[int] = []
    for entry in http_entries:
        status = str(entry.get("status", 0))
        status_counter[status] += 1
        latencies.append(int(entry.get("duration_ms", 0)))

    latencies.sort()
    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)
    avg = sum(latencies) / len(latencies) if latencies else 0.0

    lines.append(f"- 总请求数: {total}")
    lines.append("- 状态码分布:")
    for status in sorted(status_counter.keys()):
        count = status_counter[status]
        pct = count * 100.0 / total if total else 0.0
        lines.append(f"  - `{status}`: {count} ({pct:.2f}%)")
    lines.append(f"- 平均延迟: {avg:.2f} ms")
    lines.append(f"- P50 延迟: {p50} ms")
    lines.append(f"- P95 延迟: {p95} ms")
    lines.append(f"- P99 延迟: {p99} ms")
    lines.append("")
    return "\n".join(lines)


def section_perf_baseline(perf_entries: list[dict[str, Any]]) -> str:
    """生成第 2 节：性能基线对照表（实际 vs 目标）。"""
    lines: list[str] = ["## 2. 性能基线对照表", ""]
    lines.append(
        "| 测试名 | Endpoint | 目标 P99 (ms) | 实际 P99 (ms) | "
        "目标 RPS | 实际 RPS | 目标错误率 (%) | 实际错误率 (%) | 结果 |"
    )
    lines.append(
        "|--------|----------|--------------|--------------|"
        "----------|----------|----------------|----------------|------|"
    )

    # 按 test_name 索引实际数据，允许同一 test_name 多次运行取最新一条
    # LOW-7: 用 ts 字段（RFC3339）字典序比较取真正最新一条，
    # 而非依赖 perf_entries 列表顺序（顺序可能非时间序）
    latest_by_name: dict[str, dict[str, Any]] = {}
    latest_ts: dict[str, str] = {}
    for entry in perf_entries:
        name = entry.get("test_name", "")
        ts = entry.get("ts", "")
        if name not in latest_by_name or ts > latest_ts[name]:
            latest_by_name[name] = entry
            latest_ts[name] = ts

    for test_name, endpoint, t_p99, t_rps, t_err in PERF_TARGETS:
        actual = latest_by_name.get(test_name)
        if actual is None:
            lines.append(
                f"| {test_name} | `{endpoint}` | {t_p99} | N/A | "
                f"{t_rps} | N/A | {t_err} | N/A | ❌ 未运行 |"
            )
            continue
        a_p99 = int(actual.get("p99_ms", 0))
        a_rps = int(actual.get("rps", 0))
        a_total = int(actual.get("total", 0))
        a_errors = int(actual.get("errors", 0))
        a_err_pct = (a_errors * 100.0 / a_total) if a_total else 100.0
        ok = a_p99 < t_p99 and a_rps >= t_rps and a_err_pct < t_err
        mark = "✅ 达标" if ok else "❌ 不达标"
        lines.append(
            f"| {test_name} | `{endpoint}` | {t_p99} | {a_p99} | "
            f"{t_rps} | {a_rps} | {t_err} | {a_err_pct:.4f} | {mark} |"
        )

    lines.append("")
    return "\n".join(lines)


def section_pentest_matrix(pentest_entries: list[dict[str, Any]]) -> str:
    """生成第 3 节：渗透测试矩阵（7 类攻击 × N payload）。"""
    lines: list[str] = ["## 3. 渗透测试矩阵", ""]
    if not pentest_entries:
        lines.extend(["- 无渗透测试 finding 数据", ""])
        return "\n".join(lines)

    # 按 attack_type 分组
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in pentest_entries:
        attack_type = entry.get("attack_type", "unknown")
        by_type[attack_type].append(entry)

    total_findings = len(pentest_entries)
    bypassed_total = sum(1 for e in pentest_entries if e.get("bypassed", False))
    lines.append(f"- 总 finding 数: {total_findings}")
    lines.append(f"- 总绕过数 (bypassed=true): {bypassed_total}")
    lines.append("")

    # 表格：覆盖 7 类攻击
    lines.append("| 攻击类型 | Payload 数 | Bypassed | Critical | High | Medium | Low | Info |")
    lines.append("|---------|-----------|----------|----------|------|--------|-----|------|")
    for attack_type in ATTACK_TYPES:
        findings = by_type.get(attack_type, [])
        n_payload = len(findings)
        n_bypassed = sum(1 for f in findings if f.get("bypassed", False))
        sev_counter: Counter[str] = Counter()
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            sev_counter[sev] += 1
        lines.append(
            f"| {attack_type} | {n_payload} | {n_bypassed} | "
            f"{sev_counter.get('critical', 0)} | "
            f"{sev_counter.get('high', 0)} | "
            f"{sev_counter.get('medium', 0)} | "
            f"{sev_counter.get('low', 0)} | "
            f"{sev_counter.get('info', 0)} |"
        )

    # 其他未分类
    other_types = set(by_type.keys()) - set(ATTACK_TYPES)
    if other_types:
        other_findings: list[dict[str, Any]] = []
        for t in other_types:
            other_findings.extend(by_type[t])
        n_bypassed = sum(1 for f in other_findings if f.get("bypassed", False))
        sev_counter = Counter(str(f.get("severity", "info")).lower() for f in other_findings)
        lines.append(
            f"| _other_ | {len(other_findings)} | {n_bypassed} | "
            f"{sev_counter.get('critical', 0)} | "
            f"{sev_counter.get('high', 0)} | "
            f"{sev_counter.get('medium', 0)} | "
            f"{sev_counter.get('low', 0)} | "
            f"{sev_counter.get('info', 0)} |"
        )

    lines.append("")

    # 详细 finding 列表（按 attack_type 分组）
    lines.append("### 详细 finding 列表")
    lines.append("")
    for attack_type in ATTACK_TYPES:
        findings = by_type.get(attack_type, [])
        if not findings:
            continue
        lines.append(f"#### {attack_type} ({len(findings)} payloads)")
        lines.append("")
        lines.append("| Payload | Endpoint | Status | Bypassed | Severity | Snippet |")
        lines.append("|---------|----------|--------|----------|----------|---------|")
        for f in findings:
            payload = str(f.get("payload", ""))
            # 转义 | 防止破坏表格
            payload = payload.replace("|", "\\|").replace("\n", " ")[:60]
            endpoint = str(f.get("endpoint", "")).replace("|", "\\|")
            status = f.get("status", "")
            bypassed = "✓" if f.get("bypassed", False) else "✗"
            severity = str(f.get("severity", "info"))
            snippet = str(f.get("response_snippet", "")).replace("|", "\\|").replace("\n", " ")[:60]
            lines.append(
                f"| `{payload}` | `{endpoint}` | {status} | {bypassed} | {severity} | {snippet} |"
            )
        lines.append("")

    return "\n".join(lines)


def section_anomalies(http_entries: list[dict[str, Any]]) -> str:
    """生成第 4 节：异常请求列表（5xx / 超时 / 响应体 >4KB）。"""
    lines: list[str] = ["## 4. 异常请求列表", ""]
    if not http_entries:
        lines.extend(["- 无 HTTP 交互数据", ""])
        return "\n".join(lines)

    # LOW-7: 单次遍历 http_entries 同时筛 5xx / 超时 / oversized，避免 3 次遍历
    # LOW-8: oversized 缓存 body_size，避免输出时重复调用 resp_body_size
    timeout_threshold_ms = 5000
    five_xx: list[dict[str, Any]] = []
    timeouts: list[dict[str, Any]] = []
    oversized: list[tuple[dict[str, Any], int]] = []  # (entry, body_size)
    for e in http_entries:
        status = int(e.get("status", 0))
        if status >= 500:
            five_xx.append(e)
        if int(e.get("duration_ms", 0)) >= timeout_threshold_ms:
            timeouts.append(e)
        body_size = resp_body_size(e.get("resp_body"))
        if body_size > OVERSIZE_THRESHOLD:
            oversized.append((e, body_size))

    lines.append(f"### 4.1 5xx 请求 ({len(five_xx)} 条)")
    lines.append("")
    if five_xx:
        lines.append("| Test | Method | URL | Status | Duration (ms) |")
        lines.append("|------|--------|-----|--------|---------------|")
        for e in five_xx[:50]:  # 限制最多 50 条
            lines.append(
                f"| {e.get('test_name', '')} | {e.get('method', '')} | "
                f"`{e.get('url', '')}` | {e.get('status', '')} | "
                f"{e.get('duration_ms', 0)} |"
            )
        if len(five_xx) > 50:
            lines.append(f"\n_...and {len(five_xx) - 50} more_")
    else:
        lines.append("- 无 5xx 请求")
    lines.append("")

    lines.append(f"### 4.2 超时请求 (≥ {timeout_threshold_ms} ms, {len(timeouts)} 条)")
    lines.append("")
    if timeouts:
        lines.append("| Test | Method | URL | Status | Duration (ms) |")
        lines.append("|------|--------|-----|--------|---------------|")
        for e in timeouts[:50]:
            lines.append(
                f"| {e.get('test_name', '')} | {e.get('method', '')} | "
                f"`{e.get('url', '')}` | {e.get('status', '')} | "
                f"{e.get('duration_ms', 0)} |"
            )
        if len(timeouts) > 50:
            lines.append(f"\n_...and {len(timeouts) - 50} more_")
    else:
        lines.append("- 无超时请求")
    lines.append("")

    lines.append(f"### 4.3 响应体 > 4KB ({len(oversized)} 条)")
    lines.append("")
    if oversized:
        lines.append("| Test | Method | URL | Status | Body Bytes |")
        lines.append("|------|--------|-----|--------|------------|")
        for e, body_size in oversized[:50]:
            lines.append(
                f"| {e.get('test_name', '')} | {e.get('method', '')} | "
                f"`{e.get('url', '')}` | {e.get('status', '')} | {body_size} |"
            )
        if len(oversized) > 50:
            lines.append(f"\n_...and {len(oversized) - 50} more_")
    else:
        lines.append("- 无 oversized 响应")
    lines.append("")

    return "\n".join(lines)


def build_report(log_dir: Path) -> tuple[str, int]:
    """聚合 4 节内容生成完整 Markdown 报告。

    返回 (report_text, http_total)，其中 http_total 为 HTTP 交互日志行数
    （避免在 main 中用 `report.count('总请求数')` 统计字符串出现次数——
    该写法在报告含多节"总请求数"字样时恒为 1，MEDIUM-1 修复）。
    """
    http_path = log_dir / "e2e_http.jsonl"
    perf_path = log_dir / "perf.jsonl"
    pentest_path = log_dir / "pentest_report.json"

    http_entries = read_jsonl(http_path)
    perf_entries = read_jsonl(perf_path)
    pentest_entries = read_jsonl(pentest_path)

    header = [
        "# Bulwark E2E 测试综合报告",
        "",
        f"- 日志目录: `{log_dir}`",
        f"- HTTP 交互日志: `{http_path}` "
        f"({len(http_entries)} 行)"
        f"{', 存在' if http_path.exists() else ' (不存在)'}",
        f"- 性能日志: `{perf_path}` "
        f"({len(perf_entries)} 行)"
        f"{', 存在' if perf_path.exists() else ' (不存在)'}",
        f"- 渗透测试日志: `{pentest_path}` "
        f"({len(pentest_entries)} 行)"
        f"{', 存在' if pentest_path.exists() else ' (不存在)'}",
        "",
        "---",
        "",
    ]

    sections = [
        "\n".join(header),
        section_http_interactions(http_entries),
        section_perf_baseline(perf_entries),
        section_pentest_matrix(pentest_entries),
        section_anomalies(http_entries),
    ]

    return "\n".join(sections) + "\n", len(http_entries)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bulwark E2E 测试日志聚合分析器（生成 logs/e2e_final_report.md）"
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="日志目录（默认: logs）",
    )
    args = parser.parse_args()

    log_dir = Path(args.log_dir).resolve()
    if not log_dir.exists():
        print(f"错误: 日志目录 {log_dir} 不存在", file=sys.stderr)
        return 1

    report, http_total = build_report(log_dir)
    out_path = log_dir / "e2e_final_report.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"报告已生成: {out_path}")
    print(f"  - 总请求数: {http_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
