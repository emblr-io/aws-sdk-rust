// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The time period for when the predictions were generated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PredictionTimeRange {
    /// <p>The start time of the time period for when the predictions were generated.</p>
    pub start_time: ::std::string::String,
    /// <p>The end time of the time period for when the predictions were generated.</p>
    pub end_time: ::std::string::String,
}
impl PredictionTimeRange {
    /// <p>The start time of the time period for when the predictions were generated.</p>
    pub fn start_time(&self) -> &str {
        use std::ops::Deref;
        self.start_time.deref()
    }
    /// <p>The end time of the time period for when the predictions were generated.</p>
    pub fn end_time(&self) -> &str {
        use std::ops::Deref;
        self.end_time.deref()
    }
}
impl PredictionTimeRange {
    /// Creates a new builder-style object to manufacture [`PredictionTimeRange`](crate::types::PredictionTimeRange).
    pub fn builder() -> crate::types::builders::PredictionTimeRangeBuilder {
        crate::types::builders::PredictionTimeRangeBuilder::default()
    }
}

/// A builder for [`PredictionTimeRange`](crate::types::PredictionTimeRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PredictionTimeRangeBuilder {
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
    pub(crate) end_time: ::std::option::Option<::std::string::String>,
}
impl PredictionTimeRangeBuilder {
    /// <p>The start time of the time period for when the predictions were generated.</p>
    /// This field is required.
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The start time of the time period for when the predictions were generated.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of the time period for when the predictions were generated.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// <p>The end time of the time period for when the predictions were generated.</p>
    /// This field is required.
    pub fn end_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The end time of the time period for when the predictions were generated.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time of the time period for when the predictions were generated.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`PredictionTimeRange`](crate::types::PredictionTimeRange).
    /// This method will fail if any of the following fields are not set:
    /// - [`start_time`](crate::types::builders::PredictionTimeRangeBuilder::start_time)
    /// - [`end_time`](crate::types::builders::PredictionTimeRangeBuilder::end_time)
    pub fn build(self) -> ::std::result::Result<crate::types::PredictionTimeRange, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PredictionTimeRange {
            start_time: self.start_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_time",
                    "start_time was not specified but it is required when building PredictionTimeRange",
                )
            })?,
            end_time: self.end_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_time",
                    "end_time was not specified but it is required when building PredictionTimeRange",
                )
            })?,
        })
    }
}
