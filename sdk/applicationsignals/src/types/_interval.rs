// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The time period used to evaluate the SLO. It can be either a calendar interval or rolling interval.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Interval {
    /// <p>If the interval is a calendar interval, this structure contains the interval specifications.</p>
    CalendarInterval(crate::types::CalendarInterval),
    /// <p>If the interval is a rolling interval, this structure contains the interval specifications.</p>
    RollingInterval(crate::types::RollingInterval),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl Interval {
    /// Tries to convert the enum instance into [`CalendarInterval`](crate::types::Interval::CalendarInterval), extracting the inner [`CalendarInterval`](crate::types::CalendarInterval).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_calendar_interval(&self) -> ::std::result::Result<&crate::types::CalendarInterval, &Self> {
        if let Interval::CalendarInterval(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CalendarInterval`](crate::types::Interval::CalendarInterval).
    pub fn is_calendar_interval(&self) -> bool {
        self.as_calendar_interval().is_ok()
    }
    /// Tries to convert the enum instance into [`RollingInterval`](crate::types::Interval::RollingInterval), extracting the inner [`RollingInterval`](crate::types::RollingInterval).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_rolling_interval(&self) -> ::std::result::Result<&crate::types::RollingInterval, &Self> {
        if let Interval::RollingInterval(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`RollingInterval`](crate::types::Interval::RollingInterval).
    pub fn is_rolling_interval(&self) -> bool {
        self.as_rolling_interval().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
