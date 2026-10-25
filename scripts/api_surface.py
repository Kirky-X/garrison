#!/usr/bin/env python3
# Copyright (c) 2026 Kirky.X🌠
# SPDX-License-Identifier: Apache-2.0
"""解析 rustdoc JSON，输出 garrison 公共 API 面基线。

用法：
    python3 scripts/api_surface.py target/doc/garrison.json > logs/api-surface.txt
    python3 scripts/api_surface.py target/doc/garrison.json --diff logs/api-surface.baseline.txt

输出格式：`<kind>\\t<path>\\t<signature>`，按路径排序。
`<signature>` 是该项的签名/类型指纹（可读渲染）：函数渲染参数与返回类型，
结构体/枚举渲染公开字段与变体，trait 渲染方法签名，type alias / 常量 / 静态项
渲染其类型；无签名维度的项（module）为空串。

`--diff` 打印新增/移除/修改项。`modified` 覆盖两类变化：**kind 变化**与
**签名/类型层面变化**（同一路径下签名指纹不同）——后者是既有公共项的破坏性
变更，只看 kind 会漏判。report-only，退出码 0。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------- 类型渲染


def _render_args(args: Any) -> str:
    """渲染泛型实参列表（rustdoc JSON 的 angle_bracketed 形态）。"""
    if not isinstance(args, dict):
        return ""
    angled = args.get("angle_bracketed")
    if not isinstance(angled, dict):
        return ""
    parts: list[str] = []
    for arg in angled.get("args") or []:
        if isinstance(arg, dict) and "type" in arg:
            parts.append(_render_type(arg["type"]))
        else:
            parts.append(_render_type(arg))
    constraints = _render_constraints(angled.get("constraints"))
    if constraints:
        parts.append(constraints)
    if not parts:
        return ""
    return "<" + ", ".join(parts) + ">"


def _render_constraints(constraints: Any) -> str:
    """渲染关联类型约束（angle_bracketed.constraints）。"""
    parts: list[str] = []
    for constraint in constraints or []:
        name = constraint.get("name", "?")
        binding = constraint.get("binding") or {}
        if "equality" in binding:
            parts.append(f"{name} = {_render_type(binding['equality'].get('type'))}")
        elif "type" in binding:
            parts.append(f"{name} = {_render_type(binding['type'].get('type'))}")
        else:
            parts.append(f"{name} = ?")
    return ", ".join(parts)


def _render_trait(node: Any) -> str:
    """渲染 trait 引用（trait bound / dyn trait 成员）。

    两种形态：直接给 `{"trait": {...}}`，或包一层 `{"trait_bound": {...}}`。
    """
    if not isinstance(node, dict):
        return "?"
    bound = node.get("trait_bound")
    inner = bound if isinstance(bound, dict) else node
    trait = inner.get("trait")
    if not isinstance(trait, dict):
        return "?"
    return f"{trait.get('path', '?')}{_render_args(trait.get('args'))}"


def _fallback(node: Any) -> str:
    """未知类型形态的兜底渲染：取内容摘要，保留「变化可见性」。

    直接渲染成固定占位符会让该子树的任何变化都不可见；摘要随内容变化，
    变化仍能被 diff 识别。
    """
    canonical = json.dumps(node, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"#{digest}"


def _render_type(node: Any) -> str:
    """把 rustdoc JSON 的类型节点渲染为可读文本。"""
    if not isinstance(node, dict):
        return "?"
    if "primitive" in node:
        return str(node["primitive"])
    if "generic" in node:
        return str(node["generic"])
    if "lifetime" in node:
        return str(node["lifetime"])
    if "const" in node and isinstance(node["const"], dict):
        return f"const {_render_type(node['const'].get('type'))}"
    if "resolved_path" in node:
        resolved = node["resolved_path"] or {}
        return f"{resolved.get('path', '?')}{_render_args(resolved.get('args'))}"
    if "borrowed_ref" in node:
        ref = node["borrowed_ref"] or {}
        prefix = "&"
        if ref.get("is_mutable"):
            prefix += "mut "
        lifetime = ref.get("lifetime")
        if lifetime:
            prefix += f"{lifetime} "
        return prefix + _render_type(ref.get("type"))
    if "tuple" in node:
        return "(" + ", ".join(_render_type(t) for t in node["tuple"]) + ")"
    if "slice" in node:
        return "[" + _render_type((node["slice"] or {}).get("type")) + "]"
    if "array" in node:
        array = node["array"] or {}
        return f"[{_render_type(array.get('type'))}; {array.get('len')}]"
    if "dyn_trait" in node:
        traits = (node["dyn_trait"] or {}).get("traits") or []
        return "dyn " + " + ".join(_render_trait(t) for t in traits)
    if "impl_trait" in node:
        bounds = node["impl_trait"] or []
        return "impl " + " + ".join(_render_trait(bound) for bound in bounds)
    if "function_pointer" in node:
        pointer = node["function_pointer"] or {}
        return _render_fn_body(pointer.get("sig"), pointer.get("header"))
    if "qualified_path" in node:
        qualified = node["qualified_path"] or {}
        return (
            f"{_render_type(qualified.get('self_type'))}"
            f"::{_render_trait(qualified.get('trait'))}"
        )
    if "raw_pointer" in node:
        pointer = node["raw_pointer"] or {}
        mutability = "mut" if pointer.get("is_mutable") else "const"
        return f"*{mutability} {_render_type(pointer.get('type'))}"
    if "infer" in node:
        return "_"
    return _fallback(node)


def _render_generics(generics: Any) -> str:
    """渲染泛型参数列表与 where 约束。"""
    if not isinstance(generics, dict):
        return ""
    names: list[str] = []
    for param in generics.get("params") or []:
        name = str(param.get("name", "?"))
        kind = param.get("kind") or {}
        if "lifetime" in kind:
            lifetime = kind["lifetime"] or {}
            outlives = ", ".join(str(x) for x in lifetime.get("outlives") or [])
            name = name.lstrip("'")
            names.append(f"'{name}: {outlives}" if outlives else f"'{name}")
        elif "type" in kind:
            type_kind = kind["type"] or {}
            bounds = type_kind.get("bounds") or []
            rendered = ", ".join(_render_trait(bound) for bound in bounds)
            text = f"{name}: {rendered}" if rendered else name
            default = type_kind.get("default")
            if default is not None:
                text += f" = {_render_type(default)}"
            names.append(text)
        elif "const" in kind:
            const_kind = kind["const"] or {}
            text = f"const {name}: {_render_type(const_kind.get('type'))}"
            default = const_kind.get("default")
            if default is not None:
                text += f" = {json.dumps(default, sort_keys=True, ensure_ascii=False, default=str)}"
            names.append(text)
        else:
            names.append(name)
    text = "<" + ", ".join(names) + ">" if names else ""
    predicates = generics.get("where_predicates") or []
    if predicates:
        rendered_predicates = "; ".join(_render_where_predicate(p) for p in predicates)
        text += f" where {rendered_predicates}"
    return text


def _render_where_predicate(predicate: Any) -> str:
    """渲染 where 约束（bound / lifetime / eq 三类）。

    键名是 `bound_predicate` / `lifetime_predicate` / `eq_predicate`，直接
    挂在谓词对象上（没有 predicate_type 包裹层）；键名写错会让所有 where
    子句静默塌缩成 "?"，约束变更在指纹上不可见。
    """
    if not isinstance(predicate, dict):
        return "?"
    if "bound_predicate" in predicate:
        bound = predicate["bound_predicate"] or {}
        bounds = ", ".join(_render_trait(b) for b in bound.get("bounds") or [])
        return f"{_render_type(bound.get('type'))}: {bounds}"
    if "lifetime_predicate" in predicate:
        lifetime = predicate["lifetime_predicate"] or {}
        outlives = ", ".join(str(x) for x in lifetime.get("outlives") or [])
        return f"{lifetime.get('lifetime', '?')}: {outlives}"
    if "eq_predicate" in predicate:
        eq = predicate["eq_predicate"] or {}
        return f"{_render_type(eq.get('lhs'))} = {_render_type(eq.get('rhs'))}"
    return "?"


def _render_fn_body(sig: Any, header: Any = None) -> str:
    """渲染函数签名主体（参数 + 返回类型 + async/const/unsafe/ABI/变参修饰）。

    rustdoc JSON 中 `header` 是 function/function_pointer 节点里与 `sig`
    平级的兄弟字段（sig 内只有 inputs/is_c_variadic/output）——必须由
    调用方显式传入，缺失时 async/const/unsafe/ABI 变更在指纹上不可见。
    """
    if not isinstance(sig, dict):
        return "fn()"
    inputs = sig.get("inputs") or []
    parts: list[str] = []
    for entry in inputs:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            parts.append(f"{entry[0]}: {_render_type(entry[1])}")
        else:
            parts.append(_render_type(entry))
    if sig.get("is_c_variadic"):
        parts.append("...")
    if not isinstance(header, dict):
        header = {}
    prefix = ""
    if header.get("is_unsafe"):
        prefix += "unsafe "
    if header.get("is_const"):
        prefix += "const "
    if header.get("is_async"):
        prefix += "async "
    abi = header.get("abi")
    if isinstance(abi, str):
        if abi != "Rust":
            prefix += f'extern "{abi}" '
    elif isinstance(abi, dict) and abi:
        prefix += f'extern "{next(iter(abi))}" '
    text = f"{prefix}fn({', '.join(parts)})"
    output = sig.get("output")
    if output is not None:
        text += " -> " + _render_type(output)
    return text


# ------------------------------------------------------------ 签名指纹计算


def _item(index: dict[str, Any], item_id: Any) -> dict[str, Any]:
    """按 id 取 index 条目（rustdoc JSON 的 key 是字符串）。"""
    if item_id is None:
        return {}
    return index.get(str(item_id)) or {}


def _render_fields(index: dict[str, Any], field_ids: Any) -> str:
    """渲染公开字段列表（name: type）。"""
    parts: list[str] = []
    for field_id in field_ids or []:
        field = _item(index, field_id)
        if not field:
            continue
        inner = field.get("inner") or {}
        if "struct_field" not in inner:
            continue
        parts.append(f"{field.get('name', '?')}: {_render_type(inner['struct_field'])}")
    return ", ".join(parts)


def _render_variant(index: dict[str, Any], variant_id: Any) -> str:
    """渲染枚举变体（名称 + 载荷形态）。"""
    variant = _item(index, variant_id)
    inner = variant.get("inner") or {}
    if "variant" not in inner:
        return str(variant.get("name", "?"))
    body = inner["variant"]
    kind = body.get("kind")
    name = str(variant.get("name", "?"))
    if isinstance(kind, str):
        return name  # plain = 无载荷变体
    if isinstance(kind, dict):
        if "struct" in kind:
            fields = _render_fields(index, (kind["struct"] or {}).get("fields"))
            return f"{name} {{ {fields} }}" if fields else f"{name} {{ }}"
        if "tuple" in kind:
            fields = _render_fields(index, kind["tuple"])
            return f"{name}({fields})"
    return name


def _render_inherent_members(index: dict[str, Any], impl_ids: Any) -> str:
    """渲染类型的固有实现公开成员（方法签名等）。

    rustdoc 的 `paths` 不含固有方法与 trait 方法（它们不在公共路径表里），
    只看 `paths` 会漏掉方法级签名变更；此处把固有实现的公开成员并入类型签名。
    """
    members: list[str] = []
    for impl_id in impl_ids or []:
        impl_item = _item(index, impl_id)
        impl_body = (impl_item.get("inner") or {}).get("impl") or {}
        if impl_body.get("trait") is not None:
            continue  # trait 实现的方法属于 trait 面，不并入类型自身签名
        if impl_body.get("is_synthetic"):
            continue  # derive 生成的方法不计入
        for member_id in impl_body.get("items") or []:
            member = _item(index, member_id)
            if not member:
                continue
            if member.get("visibility") not in ("public", "default"):
                continue
            member_inner = member.get("inner") or {}
            name = str(member.get("name", "?"))
            if "function" in member_inner:
                function = member_inner["function"]
                body = function.get("sig") or {}
                generics = _render_generics(function.get("generics"))
                members.append(
                    f"{name} {_render_fn_body(body, function.get('header'))}{generics}"
                )
            elif "constant" in member_inner:
                constant = member_inner["constant"] or {}
                members.append(f"const {name}: {_render_type(constant.get('type'))}")
            elif "type_alias" in member_inner:
                alias = member_inner["type_alias"] or {}
                members.append(f"type {name} = {_render_type(alias.get('type'))}")
    return "; ".join(sorted(members))


def _render_trait_items(index: dict[str, Any], item_ids: Any) -> str:
    """渲染 trait 成员（方法签名 + 关联类型/常量）。"""
    members: list[str] = []
    for member_id in item_ids or []:
        member = _item(index, member_id)
        if not member:
            continue
        member_inner = member.get("inner") or {}
        name = str(member.get("name", "?"))
        if "function" in member_inner:
            function = member_inner["function"]
            body = function.get("sig") or {}
            generics = _render_generics(function.get("generics"))
            members.append(
                f"{name} {_render_fn_body(body, function.get('header'))}{generics}"
            )
        elif "type_alias" in member_inner:
            alias = member_inner["type_alias"] or {}
            members.append(f"type {name} = {_render_type(alias.get('type'))}")
        elif "constant" in member_inner:
            constant = member_inner["constant"] or {}
            members.append(f"const {name}: {_render_type(constant.get('type'))}")
        else:
            members.append(f"{name}: <{','.join(sorted(member_inner.keys())) or '?'}>")
    return "; ".join(sorted(members))


def signature_of(index: dict[str, Any], item: dict[str, Any]) -> str:
    """计算公共项的签名/类型指纹（空串表示无签名维度）。"""
    inner = item.get("inner") or {}
    if "function" in inner:
        function = inner["function"]
        body = function.get("sig") or {}
        generics = _render_generics(function.get("generics"))
        return f"{_render_fn_body(body, function.get('header'))}{generics}"
    if "struct" in inner:
        struct = inner["struct"]
        kind_body = struct.get("kind") or {}
        generics = _render_generics(struct.get("generics"))
        members = _render_inherent_members(index, struct.get("impls"))
        if "plain" in kind_body:
            fields = _render_fields(index, (kind_body["plain"] or {}).get("fields"))
            body_text = f"struct{generics} {{ {fields} }}"
        elif "tuple" in kind_body:
            fields = _render_fields(index, kind_body["tuple"])
            body_text = f"struct{generics}({fields})"
        else:
            body_text = f"struct{generics}"
        return f"{body_text}; {members}" if members else body_text
    if "enum" in inner:
        enum = inner["enum"]
        generics = _render_generics(enum.get("generics"))
        variants = [_render_variant(index, vid) for vid in enum.get("variants") or []]
        body_text = f"enum{generics} {{ {', '.join(variants)} }}"
        members = _render_inherent_members(index, enum.get("impls"))
        return f"{body_text}; {members}" if members else body_text
    if "union" in inner:
        union = inner["union"]
        generics = _render_generics(union.get("generics"))
        fields = _render_fields(index, union.get("fields"))
        members = _render_inherent_members(index, union.get("impls"))
        body_text = f"union{generics} {{ {fields} }}"
        return f"{body_text}; {members}" if members else body_text
    if "trait" in inner:
        trait = inner["trait"]
        # is_unsafe/is_auto/is_dyn_compatible 都是破坏性变更维度：
        # trait 加 unsafe / 转 auto / 变 dyn 不兼容，实现方与调用方全部受影响。
        prefix = ""
        if trait.get("is_unsafe"):
            prefix += "unsafe "
        if trait.get("is_auto"):
            prefix += "auto "
        generics = _render_generics(trait.get("generics"))
        bounds = ", ".join(_render_trait(bound) for bound in trait.get("bounds") or [])
        members = _render_trait_items(index, trait.get("items"))
        body_text = f"{prefix}trait{generics}: {bounds} {{ {members} }}"
        if not trait.get("is_dyn_compatible", True):
            body_text += " !dyn_compatible"
        return body_text
    if "type_alias" in inner:
        alias = inner["type_alias"]
        generics = _render_generics(alias.get("generics"))
        return f"type = {_render_type(alias.get('type'))}{generics}"
    if "constant" in inner:
        constant = inner["constant"]
        expression = (constant.get("const") or {}).get("expr")
        return f"const: {_render_type(constant.get('type'))} = {expression}"
    if "static" in inner:
        static = inner["static"]
        mutability = "mut" if static.get("is_mutable") else "imm"
        return f"static {mutability}: {_render_type(static.get('type'))}"
    if "macro" in inner:
        digest = hashlib.sha256(str(inner["macro"]).encode("utf-8")).hexdigest()[:12]
        return f"macro_rules sha256:{digest}"
    if "variant" in inner:
        discriminant = inner["variant"].get("discriminant")
        suffix = f" = {discriminant}" if discriminant is not None else ""
        return f"variant{suffix}"
    return ""


# ---------------------------------------------------------------- 采集与差分


def collect(doc: dict) -> list[tuple[str, str, str]]:
    """收集公共项（优先用 paths 的完整路径，缺失时回退到 index 名称）。"""
    index = doc.get("index", {})
    paths = doc.get("paths", {})
    rows: list[tuple[str, str, str]] = []

    for item_id, meta in paths.items():
        item = index.get(item_id, {})
        visibility = item.get("visibility")
        if visibility is not None and visibility != "public":
            continue
        path = meta.get("path") or []
        if not path or path[0] != "garrison":
            continue
        kind = meta.get("kind") or "unknown"
        rows.append((kind, "::".join(path), signature_of(index, item)))

    if not rows:
        for item in index.values():
            if item.get("visibility") != "public":
                continue
            name = item.get("name")
            if not name:
                continue
            inner = item.get("inner") or {}
            kind = next(iter(inner), "unknown")
            rows.append((kind, name, signature_of(index, item)))

    return sorted(set(rows))


def read_baseline(path: Path) -> dict[str, tuple[str, str]]:
    """读取基线文件，返回 {公共路径: (kind, signature)}。

    兼容旧版两列基线（无 signature 列）：此时 signature 为空串，签名级变更
    无法识别——调用方据此显式告警，不静默当作「无变化」。
    """
    rows: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t", 2)
        kind = parts[0]
        api_path = parts[1] if len(parts) > 1 else ""
        signature = parts[2] if len(parts) > 2 else ""
        if api_path:
            rows[api_path] = (kind, signature)
    return rows


def diff_surfaces(
    baseline: dict[str, tuple[str, str]],
    current: dict[str, tuple[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """计算公共面差异。

    `modified` 覆盖 kind 变化与签名/类型层面变化（同一路径、签名指纹不同）；
    双方签名任一为空时不可比，不计入 modified（调用方显式告警）。
    """
    added = [
        {"kind": kind, "path": api_path}
        for api_path, (kind, _) in sorted(current.items())
        if api_path not in baseline
    ]
    removed = [
        {"kind": kind, "path": api_path}
        for api_path, (kind, _) in sorted(baseline.items())
        if api_path not in current
    ]
    modified: list[dict[str, Any]] = []
    for api_path in sorted(set(baseline) & set(current)):
        base_kind, base_signature = baseline[api_path]
        curr_kind, curr_signature = current[api_path]
        kind_changed = base_kind != curr_kind
        signature_changed = (
            bool(base_signature)
            and bool(curr_signature)
            and base_signature != curr_signature
        )
        if not (kind_changed or signature_changed):
            continue
        entry: dict[str, Any] = {
            "path": api_path,
            "from": base_kind,
            "to": curr_kind,
            "kind_changed": kind_changed,
            "signature_changed": signature_changed,
        }
        if signature_changed:
            entry["baseline_signature"] = base_signature
            entry["current_signature"] = curr_signature
        modified.append(entry)
    return {"added": added, "removed": removed, "modified": modified}


def write_diff_json(
    path: Path,
    baseline: dict[str, tuple[str, str]],
    current: dict[str, tuple[str, str]],
) -> dict[str, object]:
    """写出结构化公共 API 差异（report-only）。"""
    diff = diff_surfaces(baseline, current)
    payload: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_total": len(baseline),
        "current_total": len(current),
        "added": diff["added"],
        "removed": diff["removed"],
        "modified": diff["modified"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def _change_label(entry: dict[str, Any]) -> str:
    """把差异条目渲染成一行可读标签。"""
    parts: list[str] = []
    if entry.get("kind_changed"):
        parts.append(f"kind:{entry.get('from')}->{entry.get('to')}")
    if entry.get("signature_changed"):
        parts.append("signature")
    return "+".join(parts) or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description="garrison 公共 API 面基线")
    parser.add_argument("json", type=Path, help="rustdoc JSON 路径")
    parser.add_argument("--diff", type=Path, help="基线文件；打印新增/移除/修改项")
    parser.add_argument(
        "--diff-json",
        type=Path,
        help="结构化差异 JSON 输出路径（默认 logs/api-surface-diff.json）",
    )
    args = parser.parse_args()

    if not args.json.is_file():
        print(f"api-surface: JSON 不存在: {args.json}", file=sys.stderr)
        return 2

    doc = json.loads(args.json.read_text(encoding="utf-8"))
    rows = collect(doc)

    for kind, api_path, signature in rows:
        print(f"{kind}\t{api_path}\t{signature}")
    print(f"# total: {len(rows)}", file=sys.stderr)

    if args.diff:
        if not args.diff.is_file():
            print(f"api-surface: 基线不存在: {args.diff}", file=sys.stderr)
            return 2
        baseline = read_baseline(args.diff)
        current = {api_path: (kind, signature) for kind, api_path, signature in rows}
        diff_json = args.diff_json or Path("logs/api-surface-diff.json")
        payload = write_diff_json(diff_json, baseline, current)
        modified = payload["modified"]
        print(
            f"# diff vs {args.diff}: +{len(payload['added'])} -{len(payload['removed'])} "
            f"~{len(modified)} -> {diff_json}",
            file=sys.stderr,
        )
        if baseline and not any(signature for _, signature in baseline.values()):
            print(
                "# 警告: 基线文件无 signature 列（旧版脚本产物），签名级变更不可识别",
                file=sys.stderr,
            )
        for kind, api_path in payload["added"]:
            print(f"+{kind}\t{api_path}", file=sys.stderr)
        for kind, api_path in payload["removed"]:
            print(f"-{kind}\t{api_path}", file=sys.stderr)
        for item in modified:
            print(f"~{item['path']}\t{_change_label(item)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
