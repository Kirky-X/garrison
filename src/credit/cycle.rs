//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 配额周期模型。
//!
//! 提供 `CreditCycle` 枚举，支持固定窗口（自然月）和滚动窗口两种周期模式。

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// Credit 配额周期模式。
///
/// 决定 credit 计数何时重置为零。
///
/// # 变体
///
/// - `Fixed`：每月固定日期 00:00 UTC 重置（`day_of_month` 范围 1..=28）
/// - `Rolling`：从首次消费起 N 天后重置
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditCycle {
    /// 固定窗口：每月 `day_of_month` 日 00:00 UTC 重置。
    ///
    /// `day_of_month` 范围 1..=28（避免 29/30/31 月问题）。
    Fixed {
        /// 重置日（1..=28）。
        day_of_month: u32,
    },
    /// 滚动窗口：首次消费起 `days` 天后重置。
    Rolling {
        /// 窗口天数。
        days: u32,
    },
}

impl CreditCycle {
    /// 计算当前周期的起始时间（Unix 时间戳）。
    ///
    /// # 参数
    /// - `window_start`: 滚动窗口的起始时间戳（仅 `Rolling` 模式使用）。
    ///   `None` 表示尚未开始（首次消费），返回当前时间。
    /// - `now`: 当前时间。
    pub fn cycle_start(&self, window_start: Option<i64>, now: NaiveDateTime) -> i64 {
        match self {
            CreditCycle::Fixed { day_of_month } => {
                let day = *day_of_month;
                // 若当前日 >= day，周期起始为本月 day 日
                // 若当前日 < day，周期起始为上月 day 日
                let (year, month, current_day) = (now.year(), now.month(), now.day());
                if current_day >= day {
                    chrono::NaiveDate::from_ymd_opt(year, month, day)
                        .unwrap_or_else(|| {
                            // day > 当月天数时回退到当月最后一天
                            chrono::NaiveDate::from_ymd_opt(
                                year,
                                month,
                                last_day_of_month(year, month),
                            )
                            .unwrap()
                        })
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp()
                } else {
                    // 上月 day 日
                    let (prev_year, prev_month) = if month == 1 {
                        (year - 1, 12)
                    } else {
                        (year, month - 1)
                    };
                    chrono::NaiveDate::from_ymd_opt(prev_year, prev_month, day)
                        .unwrap_or_else(|| {
                            chrono::NaiveDate::from_ymd_opt(
                                prev_year,
                                prev_month,
                                last_day_of_month(prev_year, prev_month),
                            )
                            .unwrap()
                        })
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp()
                }
            },
            CreditCycle::Rolling { .. } => {
                window_start.unwrap_or_else(|| now.and_utc().timestamp())
            },
        }
    }

    /// 计算当前周期的结束时间（Unix 时间戳）。
    ///
    /// # 参数
    /// - `window_start`: 滚动窗口的起始时间戳。
    /// - `now`: 当前时间。
    pub fn cycle_end(&self, window_start: Option<i64>, now: NaiveDateTime) -> i64 {
        match self {
            CreditCycle::Fixed { day_of_month } => {
                let day = *day_of_month;
                let (year, month, current_day) = (now.year(), now.month(), now.day());
                if current_day >= day {
                    // 下个周期起始 = 下月 day 日
                    let (next_year, next_month) = if month == 12 {
                        (year + 1, 1)
                    } else {
                        (year, month + 1)
                    };
                    chrono::NaiveDate::from_ymd_opt(next_year, next_month, day)
                        .unwrap_or_else(|| {
                            chrono::NaiveDate::from_ymd_opt(
                                next_year,
                                next_month,
                                last_day_of_month(next_year, next_month),
                            )
                            .unwrap()
                        })
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp()
                } else {
                    // 当前周期结束 = 本月 day 日
                    chrono::NaiveDate::from_ymd_opt(year, month, day)
                        .unwrap_or_else(|| {
                            chrono::NaiveDate::from_ymd_opt(
                                year,
                                month,
                                last_day_of_month(year, month),
                            )
                            .unwrap()
                        })
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp()
                }
            },
            CreditCycle::Rolling { days } => {
                let start = window_start.unwrap_or_else(|| now.and_utc().timestamp());
                start + (*days as i64) * 86400
            },
        }
    }

    /// 检查当前周期是否已过期。
    ///
    /// # 参数
    /// - `window_start`: 滚动窗口的起始时间戳。
    /// - `now`: 当前时间。
    pub fn is_expired(&self, window_start: Option<i64>, now: NaiveDateTime) -> bool {
        let end = self.cycle_end(window_start, now);
        now.and_utc().timestamp() >= end
    }

    /// 返回下次重置时间的 Unix 时间戳。
    pub fn next_reset_at(&self, window_start: Option<i64>, now: NaiveDateTime) -> i64 {
        self.cycle_end(window_start, now)
    }

    /// 返回周期类型的字符串标识（用于 meta 序列化）。
    pub fn type_tag(&self) -> &'static str {
        match self {
            CreditCycle::Fixed { .. } => "fixed",
            CreditCycle::Rolling { .. } => "rolling",
        }
    }

    /// 从 meta 中的 type tag + 参数重建 `CreditCycle`。
    ///
    /// # 参数
    /// - `type_tag`: "fixed" 或 "rolling"
    /// - `param`: fixed 模式为 day_of_month，rolling 模式为 days
    pub fn from_tag(type_tag: &str, param: u32) -> Option<Self> {
        match type_tag {
            "fixed" => Some(CreditCycle::Fixed {
                day_of_month: param,
            }),
            "rolling" => Some(CreditCycle::Rolling { days: param }),
            _ => None,
        }
    }

    /// 返回周期参数值（fixed → day_of_month，rolling → days）。
    pub fn param(&self) -> u32 {
        match self {
            CreditCycle::Fixed { day_of_month } => *day_of_month,
            CreditCycle::Rolling { days } => *days,
        }
    }
}

/// 计算指定年月的最后一天。
fn last_day_of_month(year: i32, month: u32) -> u32 {
    // 下月第 0 天 = 当月最后一天（chrono 不支持 day=0，用下月 1 日 - 1 天）
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .unwrap()
        .pred_opt()
        .unwrap()
        .day()
}

use chrono::Datelike;

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed 模式：当前日 >= day_of_month 时，周期起始为本月 day 日。
    #[test]
    fn test_fixed_cycle_start_end() {
        let cycle = CreditCycle::Fixed { day_of_month: 15 };
        // 2026-08-20 >= 15 → 周期起始 = 2026-08-15 00:00 UTC
        let now = chrono::NaiveDate::from_ymd_opt(2026, 8, 20)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let start = cycle.cycle_start(None, now);
        let expected_start = chrono::NaiveDate::from_ymd_opt(2026, 8, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(start, expected_start);

        let end = cycle.cycle_end(None, now);
        let expected_end = chrono::NaiveDate::from_ymd_opt(2026, 9, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(end, expected_end);
    }

    /// Fixed 模式：当前日 < day_of_month 时，周期起始为上月 day 日。
    #[test]
    fn test_fixed_cycle_start_before_day() {
        let cycle = CreditCycle::Fixed { day_of_month: 15 };
        // 2026-08-10 < 15 → 周期起始 = 2026-07-15 00:00 UTC
        let now = chrono::NaiveDate::from_ymd_opt(2026, 8, 10)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let start = cycle.cycle_start(None, now);
        let expected_start = chrono::NaiveDate::from_ymd_opt(2026, 7, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(start, expected_start);
    }

    /// Rolling 模式：周期起始为 window_start，结束为 window_start + days * 86400。
    #[test]
    fn test_rolling_cycle_start_end() {
        let cycle = CreditCycle::Rolling { days: 30 };
        let window_start_ts = 1_700_000_000i64;
        let now = chrono::NaiveDate::from_ymd_opt(2026, 8, 20)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let start = cycle.cycle_start(Some(window_start_ts), now);
        assert_eq!(start, window_start_ts);

        let end = cycle.cycle_end(Some(window_start_ts), now);
        assert_eq!(end, window_start_ts + 30 * 86400);
    }

    /// Fixed 模式：is_expired 在 window_start=None 时始终返回 false。
    ///
    /// 原因：Fixed 模式的 cycle_end 总是返回下一个重置日（未来时间），
    /// 没有 window_start 无法确定当前周期起始，因此无法判定过期。
    /// 实际使用中 meter 会先 check_and_reset_cycle 再调用 is_expired。
    #[test]
    fn test_fixed_cycle_is_expired_without_window_start() {
        let cycle = CreditCycle::Fixed { day_of_month: 15 };
        // cycle_end(None, 2026-09-16) = 2026-10-15（下月重置日）
        // 2026-09-16 < 2026-10-15 → not expired
        let now = chrono::NaiveDate::from_ymd_opt(2026, 9, 16)
            .unwrap()
            .and_hms_opt(0, 0, 1)
            .unwrap();
        assert!(!cycle.is_expired(None, now));

        // cycle_end(None, 2026-09-14) = 2026-09-15（本月重置日）
        // 2026-09-14 < 2026-09-15 → not expired
        let now2 = chrono::NaiveDate::from_ymd_opt(2026, 9, 14)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        assert!(!cycle.is_expired(None, now2));
    }

    /// Rolling 模式：is_expired 在当前时间超过 window_start + days 时返回 true。
    #[test]
    fn test_rolling_cycle_is_expired() {
        let cycle = CreditCycle::Rolling { days: 30 };
        let window_start_ts = 1_700_000_000i64;
        // now > window_start + 30 * 86400 → expired
        let expired_now = chrono::DateTime::from_timestamp(window_start_ts + 31 * 86400, 0)
            .unwrap()
            .naive_utc();
        assert!(cycle.is_expired(Some(window_start_ts), expired_now));

        // now < window_start + 30 * 86400 → not expired
        let active_now = chrono::DateTime::from_timestamp(window_start_ts + 15 * 86400, 0)
            .unwrap()
            .naive_utc();
        assert!(!cycle.is_expired(Some(window_start_ts), active_now));
    }

    /// Fixed 模式：day_of_month = 28 在 28 天月（二月平年）边界正确。
    #[test]
    fn test_fixed_day_of_month_boundary() {
        let cycle = CreditCycle::Fixed { day_of_month: 28 };
        // 2026-02-28（平年二月最后一天）
        let now = chrono::NaiveDate::from_ymd_opt(2026, 2, 28)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let start = cycle.cycle_start(None, now);
        let expected = chrono::NaiveDate::from_ymd_opt(2026, 2, 28)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(start, expected);
    }

    /// type_tag + from_tag 往返一致。
    #[test]
    fn test_type_tag_roundtrip() {
        let fixed = CreditCycle::Fixed { day_of_month: 15 };
        assert_eq!(fixed.type_tag(), "fixed");
        assert_eq!(fixed.param(), 15);
        let rebuilt = CreditCycle::from_tag("fixed", 15).unwrap();
        assert_eq!(rebuilt, fixed);

        let rolling = CreditCycle::Rolling { days: 30 };
        assert_eq!(rolling.type_tag(), "rolling");
        assert_eq!(rolling.param(), 30);
        let rebuilt = CreditCycle::from_tag("rolling", 30).unwrap();
        assert_eq!(rebuilt, rolling);
    }

    /// from_tag 对未知 tag 返回 None。
    #[test]
    fn test_from_tag_unknown() {
        assert!(CreditCycle::from_tag("unknown", 0).is_none());
    }
}
