// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! garrison-macros 过程宏 UI 测试。
//!
//! 放根 crate 的原因：宏展开产物引用 `garrison::` 类型，需要被测 crate 本体可依赖；
//! 而 garrison-macros 依赖 garrison 会形成发布环。根 crate 的集成测试天然链接 garrison。
//!
//! 运行方式（需 annotation-macros feature；trybuild 会把当前激活 feature 透传给子构建）：
//!
//! ```bash
//! cargo test -p garrison --features annotation-macros --test macros_ui
//! ```

#[cfg(feature = "annotation-macros")]
#[test]
fn compile_tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/sync_fn_pass.rs");
    t.pass("tests/ui/async_fn_pass.rs");
}
