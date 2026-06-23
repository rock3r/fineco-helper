//! Freshness model: snapshot data-area states plus a pure, dependency-free
//! ISO-8601-UTC → Unix-epoch parse and age-based classification. We hand-roll
//! the parse (rather than add a date crate) because the timestamps are ours and
//! always the `YYYY-MM-DDTHH:MM:SS[.fraction]Z` UTC form.

/// State of a stored data area (plan "Freshness And Failure Semantics").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessState {
    Fresh,
    Stale,
    Refreshing,
    RefreshFailed,
    AuthRequired,
    StepUpRequired,
    Missing,
}

impl FreshnessState {
    /// Stable lowercase wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FreshnessState::Fresh => "fresh",
            FreshnessState::Stale => "stale",
            FreshnessState::Refreshing => "refreshing",
            FreshnessState::RefreshFailed => "refresh_failed",
            FreshnessState::AuthRequired => "auth_required",
            FreshnessState::StepUpRequired => "step_up_required",
            FreshnessState::Missing => "missing",
        }
    }
}

/// Classify freshness from a snapshot's captured-at epoch against `now`.
///
/// `None` captured-at → [`FreshnessState::Missing`]; age strictly greater than
/// `max_age_seconds` → [`FreshnessState::Stale`]; otherwise
/// [`FreshnessState::Fresh`]. The `Refreshing` / `RefreshFailed` / `AuthRequired`
/// / `StepUpRequired` states are layered in from job state by the caller.
#[must_use]
pub fn freshness_from_age(
    captured_at_epoch: Option<i64>,
    now_epoch: i64,
    max_age_seconds: i64,
) -> FreshnessState {
    match captured_at_epoch {
        None => FreshnessState::Missing,
        Some(captured) if now_epoch.saturating_sub(captured) > max_age_seconds => {
            FreshnessState::Stale
        }
        Some(_) => FreshnessState::Fresh,
    }
}

/// Current Unix time in whole seconds (production clock).
#[must_use]
pub fn now_epoch_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (UTC only) to Unix epoch seconds.
/// Returns `None` for anything not matching that exact shape or out of range.
#[must_use]
pub fn parse_iso8601_utc(s: &str) -> Option<i64> {
    let (date, time) = s.split_once('T')?;
    let time = time.strip_suffix('Z')?;
    let (year, month, day) = parse_date(date)?;
    let (hour, minute, second) = parse_time(time)?;

    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Parse exactly `YYYY-MM-DD` into `(year, month, day)`.
fn parse_date(date: &str) -> Option<(i64, i64, i64)> {
    let b = date.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    Some((
        digits(&date[0..4])?,
        digits(&date[5..7])?,
        digits(&date[8..10])?,
    ))
}

/// Parse `HH:MM:SS` (trailing `Z` already removed), dropping an optional
/// `.fraction`.
fn parse_time(time: &str) -> Option<(i64, i64, i64)> {
    let hms = match time.split_once('.') {
        Some((hms, frac)) if !frac.is_empty() && frac.bytes().all(|c| c.is_ascii_digit()) => hms,
        Some(_) => return None,
        None => time,
    };
    let b = hms.as_bytes();
    if b.len() != 8 || b[2] != b':' || b[5] != b':' {
        return None;
    }
    Some((
        digits(&hms[0..2])?,
        digits(&hms[3..5])?,
        digits(&hms[6..8])?,
    ))
}

/// Parse an all-ASCII-digit field to `i64`.
fn digits(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from the Unix epoch (1970-01-01) for a proleptic-Gregorian date
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let month_index = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let day_of_year = (153 * month_index + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Proleptic-Gregorian `(year, month, day)` for a Unix day count (Howard
/// Hinnant's `civil_from_days`, the inverse of [`days_from_civil`]).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let month_index = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = day_of_year - (153 * month_index + 2) / 5 + 1; // [1, 31]
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    }; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Current UTC time as an `YYYY-MM-DDTHH:MM:SSZ` ISO-8601 string (production
/// clock). The inverse round-trips through [`parse_iso8601_utc`].
#[must_use]
pub fn now_iso8601_utc() -> String {
    epoch_to_iso8601_utc(now_epoch_seconds())
}

/// Format a Unix epoch (seconds) as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
#[must_use]
pub fn epoch_to_iso8601_utc(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod iso_format_tests {
    use super::{epoch_to_iso8601_utc, now_epoch_seconds, now_iso8601_utc, parse_iso8601_utc};

    #[test]
    fn known_epochs_format_correctly() {
        assert_eq!(epoch_to_iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2026-01-01T00:00:00Z used elsewhere in the suite.
        assert_eq!(epoch_to_iso8601_utc(1_767_225_600), "2026-01-01T00:00:00Z");
        // A leap day with a time-of-day.
        assert_eq!(epoch_to_iso8601_utc(1_582_982_645), "2020-02-29T13:24:05Z");
    }

    #[test]
    fn format_round_trips_through_parse() {
        for epoch in [
            0_i64,
            1_000_000,
            1_767_225_600,
            1_582_982_645,
            2_000_000_000,
        ] {
            let iso = epoch_to_iso8601_utc(epoch);
            assert_eq!(parse_iso8601_utc(&iso), Some(epoch), "round-trip {iso}");
        }
    }

    #[test]
    fn now_is_a_parseable_recent_timestamp() {
        let before = now_epoch_seconds();
        let parsed = parse_iso8601_utc(&now_iso8601_utc()).expect("now parses");
        let after = now_epoch_seconds();
        assert!(
            before <= parsed && parsed <= after,
            "now within [before, after]"
        );
    }
}
