//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

#[test]
fn compile_tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/sync_fn_pass.rs");
    t.pass("tests/ui/async_fn_pass.rs");
}
