// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonOtelError` 转换实现。

#[cfg(feature = "otlp")]
use super::GarrisonOtelError;

#[cfg(feature = "otlp")]
impl From<opentelemetry_otlp::ExporterBuildError> for GarrisonOtelError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        Self::Exporter(e.to_string())
    }
}
