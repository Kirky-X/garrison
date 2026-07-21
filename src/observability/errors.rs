//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonOtelError` 转换实现（从 mod.rs 迁移，spec R-L7-003）。

#[cfg(feature = "observability-otlp")]
use super::GarrisonOtelError;

#[cfg(feature = "observability-otlp")]
impl From<opentelemetry_otlp::ExporterBuildError> for GarrisonOtelError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        Self::Exporter(e.to_string())
    }
}
