// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Campaign schedule
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Schedule {
    /// Timestamp with no UTC offset or timezone
    pub start_time: ::aws_smithy_types::DateTime,
    /// Timestamp with no UTC offset or timezone
    pub end_time: ::aws_smithy_types::DateTime,
    /// Time duration in ISO 8601 format
    pub refresh_frequency: ::std::option::Option<::std::string::String>,
}
impl Schedule {
    /// Timestamp with no UTC offset or timezone
    pub fn start_time(&self) -> &::aws_smithy_types::DateTime {
        &self.start_time
    }
    /// Timestamp with no UTC offset or timezone
    pub fn end_time(&self) -> &::aws_smithy_types::DateTime {
        &self.end_time
    }
    /// Time duration in ISO 8601 format
    pub fn refresh_frequency(&self) -> ::std::option::Option<&str> {
        self.refresh_frequency.as_deref()
    }
}
impl Schedule {
    /// Creates a new builder-style object to manufacture [`Schedule`](crate::types::Schedule).
    pub fn builder() -> crate::types::builders::ScheduleBuilder {
        crate::types::builders::ScheduleBuilder::default()
    }
}

/// A builder for [`Schedule`](crate::types::Schedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduleBuilder {
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) refresh_frequency: ::std::option::Option<::std::string::String>,
}
impl ScheduleBuilder {
    /// Timestamp with no UTC offset or timezone
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// Timestamp with no UTC offset or timezone
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// Timestamp with no UTC offset or timezone
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// Timestamp with no UTC offset or timezone
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// Timestamp with no UTC offset or timezone
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// Timestamp with no UTC offset or timezone
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Time duration in ISO 8601 format
    pub fn refresh_frequency(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.refresh_frequency = ::std::option::Option::Some(input.into());
        self
    }
    /// Time duration in ISO 8601 format
    pub fn set_refresh_frequency(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.refresh_frequency = input;
        self
    }
    /// Time duration in ISO 8601 format
    pub fn get_refresh_frequency(&self) -> &::std::option::Option<::std::string::String> {
        &self.refresh_frequency
    }
    /// Consumes the builder and constructs a [`Schedule`](crate::types::Schedule).
    /// This method will fail if any of the following fields are not set:
    /// - [`start_time`](crate::types::builders::ScheduleBuilder::start_time)
    /// - [`end_time`](crate::types::builders::ScheduleBuilder::end_time)
    pub fn build(self) -> ::std::result::Result<crate::types::Schedule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Schedule {
            start_time: self.start_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_time",
                    "start_time was not specified but it is required when building Schedule",
                )
            })?,
            end_time: self.end_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_time",
                    "end_time was not specified but it is required when building Schedule",
                )
            })?,
            refresh_frequency: self.refresh_frequency,
        })
    }
}
