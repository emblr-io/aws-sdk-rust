// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The desired start time for an <a href="https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_OffPeakWindow.html">off-peak maintenance window</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WindowStartTime {
    /// <p>The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, <code>17</code> refers to 5:00 P.M. UTC.</p>
    pub hours: i64,
    /// <p>The start minute of the window, in UTC.</p>
    pub minutes: i64,
}
impl WindowStartTime {
    /// <p>The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, <code>17</code> refers to 5:00 P.M. UTC.</p>
    pub fn hours(&self) -> i64 {
        self.hours
    }
    /// <p>The start minute of the window, in UTC.</p>
    pub fn minutes(&self) -> i64 {
        self.minutes
    }
}
impl WindowStartTime {
    /// Creates a new builder-style object to manufacture [`WindowStartTime`](crate::types::WindowStartTime).
    pub fn builder() -> crate::types::builders::WindowStartTimeBuilder {
        crate::types::builders::WindowStartTimeBuilder::default()
    }
}

/// A builder for [`WindowStartTime`](crate::types::WindowStartTime).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WindowStartTimeBuilder {
    pub(crate) hours: ::std::option::Option<i64>,
    pub(crate) minutes: ::std::option::Option<i64>,
}
impl WindowStartTimeBuilder {
    /// <p>The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, <code>17</code> refers to 5:00 P.M. UTC.</p>
    /// This field is required.
    pub fn hours(mut self, input: i64) -> Self {
        self.hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, <code>17</code> refers to 5:00 P.M. UTC.</p>
    pub fn set_hours(mut self, input: ::std::option::Option<i64>) -> Self {
        self.hours = input;
        self
    }
    /// <p>The start hour of the window in Coordinated Universal Time (UTC), using 24-hour time. For example, <code>17</code> refers to 5:00 P.M. UTC.</p>
    pub fn get_hours(&self) -> &::std::option::Option<i64> {
        &self.hours
    }
    /// <p>The start minute of the window, in UTC.</p>
    /// This field is required.
    pub fn minutes(mut self, input: i64) -> Self {
        self.minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start minute of the window, in UTC.</p>
    pub fn set_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.minutes = input;
        self
    }
    /// <p>The start minute of the window, in UTC.</p>
    pub fn get_minutes(&self) -> &::std::option::Option<i64> {
        &self.minutes
    }
    /// Consumes the builder and constructs a [`WindowStartTime`](crate::types::WindowStartTime).
    pub fn build(self) -> crate::types::WindowStartTime {
        crate::types::WindowStartTime {
            hours: self.hours.unwrap_or_default(),
            minutes: self.minutes.unwrap_or_default(),
        }
    }
}
