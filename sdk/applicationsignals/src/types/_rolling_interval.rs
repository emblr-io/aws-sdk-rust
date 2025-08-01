// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>If the interval for this SLO is a rolling interval, this structure contains the interval specifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RollingInterval {
    /// <p>Specifies the rolling interval unit.</p>
    pub duration_unit: crate::types::DurationUnit,
    /// <p>Specifies the duration of each rolling interval. For example, if <code>Duration</code> is <code>7</code> and <code>DurationUnit</code> is <code>DAY</code>, each rolling interval is seven days.</p>
    pub duration: i32,
}
impl RollingInterval {
    /// <p>Specifies the rolling interval unit.</p>
    pub fn duration_unit(&self) -> &crate::types::DurationUnit {
        &self.duration_unit
    }
    /// <p>Specifies the duration of each rolling interval. For example, if <code>Duration</code> is <code>7</code> and <code>DurationUnit</code> is <code>DAY</code>, each rolling interval is seven days.</p>
    pub fn duration(&self) -> i32 {
        self.duration
    }
}
impl RollingInterval {
    /// Creates a new builder-style object to manufacture [`RollingInterval`](crate::types::RollingInterval).
    pub fn builder() -> crate::types::builders::RollingIntervalBuilder {
        crate::types::builders::RollingIntervalBuilder::default()
    }
}

/// A builder for [`RollingInterval`](crate::types::RollingInterval).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RollingIntervalBuilder {
    pub(crate) duration_unit: ::std::option::Option<crate::types::DurationUnit>,
    pub(crate) duration: ::std::option::Option<i32>,
}
impl RollingIntervalBuilder {
    /// <p>Specifies the rolling interval unit.</p>
    /// This field is required.
    pub fn duration_unit(mut self, input: crate::types::DurationUnit) -> Self {
        self.duration_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the rolling interval unit.</p>
    pub fn set_duration_unit(mut self, input: ::std::option::Option<crate::types::DurationUnit>) -> Self {
        self.duration_unit = input;
        self
    }
    /// <p>Specifies the rolling interval unit.</p>
    pub fn get_duration_unit(&self) -> &::std::option::Option<crate::types::DurationUnit> {
        &self.duration_unit
    }
    /// <p>Specifies the duration of each rolling interval. For example, if <code>Duration</code> is <code>7</code> and <code>DurationUnit</code> is <code>DAY</code>, each rolling interval is seven days.</p>
    /// This field is required.
    pub fn duration(mut self, input: i32) -> Self {
        self.duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the duration of each rolling interval. For example, if <code>Duration</code> is <code>7</code> and <code>DurationUnit</code> is <code>DAY</code>, each rolling interval is seven days.</p>
    pub fn set_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration = input;
        self
    }
    /// <p>Specifies the duration of each rolling interval. For example, if <code>Duration</code> is <code>7</code> and <code>DurationUnit</code> is <code>DAY</code>, each rolling interval is seven days.</p>
    pub fn get_duration(&self) -> &::std::option::Option<i32> {
        &self.duration
    }
    /// Consumes the builder and constructs a [`RollingInterval`](crate::types::RollingInterval).
    /// This method will fail if any of the following fields are not set:
    /// - [`duration_unit`](crate::types::builders::RollingIntervalBuilder::duration_unit)
    /// - [`duration`](crate::types::builders::RollingIntervalBuilder::duration)
    pub fn build(self) -> ::std::result::Result<crate::types::RollingInterval, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RollingInterval {
            duration_unit: self.duration_unit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "duration_unit",
                    "duration_unit was not specified but it is required when building RollingInterval",
                )
            })?,
            duration: self.duration.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "duration",
                    "duration was not specified but it is required when building RollingInterval",
                )
            })?,
        })
    }
}
