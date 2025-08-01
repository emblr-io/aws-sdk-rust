// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Hours of entry.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WaypointOptimizationAccessHoursEntry {
    /// <p>Day of the week.</p>
    pub day_of_week: crate::types::DayOfWeek,
    /// <p>Time of the day.</p>
    pub time_of_day: ::std::string::String,
}
impl WaypointOptimizationAccessHoursEntry {
    /// <p>Day of the week.</p>
    pub fn day_of_week(&self) -> &crate::types::DayOfWeek {
        &self.day_of_week
    }
    /// <p>Time of the day.</p>
    pub fn time_of_day(&self) -> &str {
        use std::ops::Deref;
        self.time_of_day.deref()
    }
}
impl WaypointOptimizationAccessHoursEntry {
    /// Creates a new builder-style object to manufacture [`WaypointOptimizationAccessHoursEntry`](crate::types::WaypointOptimizationAccessHoursEntry).
    pub fn builder() -> crate::types::builders::WaypointOptimizationAccessHoursEntryBuilder {
        crate::types::builders::WaypointOptimizationAccessHoursEntryBuilder::default()
    }
}

/// A builder for [`WaypointOptimizationAccessHoursEntry`](crate::types::WaypointOptimizationAccessHoursEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WaypointOptimizationAccessHoursEntryBuilder {
    pub(crate) day_of_week: ::std::option::Option<crate::types::DayOfWeek>,
    pub(crate) time_of_day: ::std::option::Option<::std::string::String>,
}
impl WaypointOptimizationAccessHoursEntryBuilder {
    /// <p>Day of the week.</p>
    /// This field is required.
    pub fn day_of_week(mut self, input: crate::types::DayOfWeek) -> Self {
        self.day_of_week = ::std::option::Option::Some(input);
        self
    }
    /// <p>Day of the week.</p>
    pub fn set_day_of_week(mut self, input: ::std::option::Option<crate::types::DayOfWeek>) -> Self {
        self.day_of_week = input;
        self
    }
    /// <p>Day of the week.</p>
    pub fn get_day_of_week(&self) -> &::std::option::Option<crate::types::DayOfWeek> {
        &self.day_of_week
    }
    /// <p>Time of the day.</p>
    /// This field is required.
    pub fn time_of_day(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_of_day = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Time of the day.</p>
    pub fn set_time_of_day(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_of_day = input;
        self
    }
    /// <p>Time of the day.</p>
    pub fn get_time_of_day(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_of_day
    }
    /// Consumes the builder and constructs a [`WaypointOptimizationAccessHoursEntry`](crate::types::WaypointOptimizationAccessHoursEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`day_of_week`](crate::types::builders::WaypointOptimizationAccessHoursEntryBuilder::day_of_week)
    /// - [`time_of_day`](crate::types::builders::WaypointOptimizationAccessHoursEntryBuilder::time_of_day)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::WaypointOptimizationAccessHoursEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WaypointOptimizationAccessHoursEntry {
            day_of_week: self.day_of_week.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "day_of_week",
                    "day_of_week was not specified but it is required when building WaypointOptimizationAccessHoursEntry",
                )
            })?,
            time_of_day: self.time_of_day.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "time_of_day",
                    "time_of_day was not specified but it is required when building WaypointOptimizationAccessHoursEntry",
                )
            })?,
        })
    }
}
