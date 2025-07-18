// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Sets the start date and end date for retrieving a cost estimate. The start date is inclusive, but the end date is exclusive. For example, if <code>start</code> is <code>2017-01-01</code> and <code>end</code> is <code>2017-05-01</code>, then the cost and usage data is retrieved from <code>2017-01-01</code> up to and including <code>2017-04-30</code> but not including <code>2017-05-01</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimePeriod {
    /// <p>The beginning of the time period. The start date is inclusive. For example, if <code>start</code> is <code>2017-01-01</code>, Lightsail for Research retrieves cost and usage data starting at <code>2017-01-01</code> up to the end date. The start date must be equal to or no later than the current date to avoid a validation error.</p>
    pub start: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time period. The end date is exclusive. For example, if <code>end</code> is <code>2017-05-01</code>, Lightsail for Research retrieves cost and usage data from the start date up to, but not including, <code>2017-05-01</code>.</p>
    pub end: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimePeriod {
    /// <p>The beginning of the time period. The start date is inclusive. For example, if <code>start</code> is <code>2017-01-01</code>, Lightsail for Research retrieves cost and usage data starting at <code>2017-01-01</code> up to the end date. The start date must be equal to or no later than the current date to avoid a validation error.</p>
    pub fn start(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start.as_ref()
    }
    /// <p>The end of the time period. The end date is exclusive. For example, if <code>end</code> is <code>2017-05-01</code>, Lightsail for Research retrieves cost and usage data from the start date up to, but not including, <code>2017-05-01</code>.</p>
    pub fn end(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end.as_ref()
    }
}
impl TimePeriod {
    /// Creates a new builder-style object to manufacture [`TimePeriod`](crate::types::TimePeriod).
    pub fn builder() -> crate::types::builders::TimePeriodBuilder {
        crate::types::builders::TimePeriodBuilder::default()
    }
}

/// A builder for [`TimePeriod`](crate::types::TimePeriod).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimePeriodBuilder {
    pub(crate) start: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimePeriodBuilder {
    /// <p>The beginning of the time period. The start date is inclusive. For example, if <code>start</code> is <code>2017-01-01</code>, Lightsail for Research retrieves cost and usage data starting at <code>2017-01-01</code> up to the end date. The start date must be equal to or no later than the current date to avoid a validation error.</p>
    pub fn start(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start = ::std::option::Option::Some(input);
        self
    }
    /// <p>The beginning of the time period. The start date is inclusive. For example, if <code>start</code> is <code>2017-01-01</code>, Lightsail for Research retrieves cost and usage data starting at <code>2017-01-01</code> up to the end date. The start date must be equal to or no later than the current date to avoid a validation error.</p>
    pub fn set_start(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start = input;
        self
    }
    /// <p>The beginning of the time period. The start date is inclusive. For example, if <code>start</code> is <code>2017-01-01</code>, Lightsail for Research retrieves cost and usage data starting at <code>2017-01-01</code> up to the end date. The start date must be equal to or no later than the current date to avoid a validation error.</p>
    pub fn get_start(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start
    }
    /// <p>The end of the time period. The end date is exclusive. For example, if <code>end</code> is <code>2017-05-01</code>, Lightsail for Research retrieves cost and usage data from the start date up to, but not including, <code>2017-05-01</code>.</p>
    pub fn end(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time period. The end date is exclusive. For example, if <code>end</code> is <code>2017-05-01</code>, Lightsail for Research retrieves cost and usage data from the start date up to, but not including, <code>2017-05-01</code>.</p>
    pub fn set_end(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end = input;
        self
    }
    /// <p>The end of the time period. The end date is exclusive. For example, if <code>end</code> is <code>2017-05-01</code>, Lightsail for Research retrieves cost and usage data from the start date up to, but not including, <code>2017-05-01</code>.</p>
    pub fn get_end(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end
    }
    /// Consumes the builder and constructs a [`TimePeriod`](crate::types::TimePeriod).
    pub fn build(self) -> crate::types::TimePeriod {
        crate::types::TimePeriod {
            start: self.start,
            end: self.end,
        }
    }
}
