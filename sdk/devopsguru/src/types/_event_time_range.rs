// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The time range during which an Amazon Web Services event occurred. Amazon Web Services resource events and metrics are analyzed by DevOps Guru to find anomalous behavior and provide recommendations to improve your operational solutions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EventTimeRange {
    /// <p>The time when the event started.</p>
    pub from_time: ::aws_smithy_types::DateTime,
    /// <p>The time when the event ended.</p>
    pub to_time: ::aws_smithy_types::DateTime,
}
impl EventTimeRange {
    /// <p>The time when the event started.</p>
    pub fn from_time(&self) -> &::aws_smithy_types::DateTime {
        &self.from_time
    }
    /// <p>The time when the event ended.</p>
    pub fn to_time(&self) -> &::aws_smithy_types::DateTime {
        &self.to_time
    }
}
impl EventTimeRange {
    /// Creates a new builder-style object to manufacture [`EventTimeRange`](crate::types::EventTimeRange).
    pub fn builder() -> crate::types::builders::EventTimeRangeBuilder {
        crate::types::builders::EventTimeRangeBuilder::default()
    }
}

/// A builder for [`EventTimeRange`](crate::types::EventTimeRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EventTimeRangeBuilder {
    pub(crate) from_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) to_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EventTimeRangeBuilder {
    /// <p>The time when the event started.</p>
    /// This field is required.
    pub fn from_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.from_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the event started.</p>
    pub fn set_from_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.from_time = input;
        self
    }
    /// <p>The time when the event started.</p>
    pub fn get_from_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.from_time
    }
    /// <p>The time when the event ended.</p>
    /// This field is required.
    pub fn to_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.to_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the event ended.</p>
    pub fn set_to_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.to_time = input;
        self
    }
    /// <p>The time when the event ended.</p>
    pub fn get_to_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.to_time
    }
    /// Consumes the builder and constructs a [`EventTimeRange`](crate::types::EventTimeRange).
    /// This method will fail if any of the following fields are not set:
    /// - [`from_time`](crate::types::builders::EventTimeRangeBuilder::from_time)
    /// - [`to_time`](crate::types::builders::EventTimeRangeBuilder::to_time)
    pub fn build(self) -> ::std::result::Result<crate::types::EventTimeRange, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EventTimeRange {
            from_time: self.from_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "from_time",
                    "from_time was not specified but it is required when building EventTimeRange",
                )
            })?,
            to_time: self.to_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "to_time",
                    "to_time was not specified but it is required when building EventTimeRange",
                )
            })?,
        })
    }
}
