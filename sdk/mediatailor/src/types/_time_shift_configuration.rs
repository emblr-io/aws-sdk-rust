// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for time-shifted viewing.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimeShiftConfiguration {
    /// <p>The maximum time delay for time-shifted viewing. The minimum allowed maximum time delay is 0 seconds, and the maximum allowed maximum time delay is 21600 seconds (6 hours).</p>
    pub max_time_delay_seconds: i32,
}
impl TimeShiftConfiguration {
    /// <p>The maximum time delay for time-shifted viewing. The minimum allowed maximum time delay is 0 seconds, and the maximum allowed maximum time delay is 21600 seconds (6 hours).</p>
    pub fn max_time_delay_seconds(&self) -> i32 {
        self.max_time_delay_seconds
    }
}
impl TimeShiftConfiguration {
    /// Creates a new builder-style object to manufacture [`TimeShiftConfiguration`](crate::types::TimeShiftConfiguration).
    pub fn builder() -> crate::types::builders::TimeShiftConfigurationBuilder {
        crate::types::builders::TimeShiftConfigurationBuilder::default()
    }
}

/// A builder for [`TimeShiftConfiguration`](crate::types::TimeShiftConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimeShiftConfigurationBuilder {
    pub(crate) max_time_delay_seconds: ::std::option::Option<i32>,
}
impl TimeShiftConfigurationBuilder {
    /// <p>The maximum time delay for time-shifted viewing. The minimum allowed maximum time delay is 0 seconds, and the maximum allowed maximum time delay is 21600 seconds (6 hours).</p>
    /// This field is required.
    pub fn max_time_delay_seconds(mut self, input: i32) -> Self {
        self.max_time_delay_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum time delay for time-shifted viewing. The minimum allowed maximum time delay is 0 seconds, and the maximum allowed maximum time delay is 21600 seconds (6 hours).</p>
    pub fn set_max_time_delay_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_time_delay_seconds = input;
        self
    }
    /// <p>The maximum time delay for time-shifted viewing. The minimum allowed maximum time delay is 0 seconds, and the maximum allowed maximum time delay is 21600 seconds (6 hours).</p>
    pub fn get_max_time_delay_seconds(&self) -> &::std::option::Option<i32> {
        &self.max_time_delay_seconds
    }
    /// Consumes the builder and constructs a [`TimeShiftConfiguration`](crate::types::TimeShiftConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`max_time_delay_seconds`](crate::types::builders::TimeShiftConfigurationBuilder::max_time_delay_seconds)
    pub fn build(self) -> ::std::result::Result<crate::types::TimeShiftConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TimeShiftConfiguration {
            max_time_delay_seconds: self.max_time_delay_seconds.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_time_delay_seconds",
                    "max_time_delay_seconds was not specified but it is required when building TimeShiftConfiguration",
                )
            })?,
        })
    }
}
