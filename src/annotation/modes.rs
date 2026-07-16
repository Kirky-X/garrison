//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 预定义模式（Strict / Loose）的 `ModeSpec` trait 实现。

use super::{Loose, ModeSpec, Strict};

impl ModeSpec for Strict {
    const STRICT: bool = true;
}

impl ModeSpec for Loose {
    const STRICT: bool = false;
}
