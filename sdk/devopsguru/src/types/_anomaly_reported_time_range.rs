// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A time range that specifies when DevOps Guru opens and then closes an anomaly. This is different from <code>AnomalyTimeRange</code>, which specifies the time range when DevOps Guru actually observes the anomalous behavior.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnomalyReportedTimeRange {
    /// <p>The time when an anomaly is opened.</p>
    pub open_time: ::aws_smithy_types::DateTime,
    /// <p>The time when an anomaly is closed.</p>
    pub close_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AnomalyReportedTimeRange {
    /// <p>The time when an anomaly is opened.</p>
    pub fn open_time(&self) -> &::aws_smithy_types::DateTime {
        &self.open_time
    }
    /// <p>The time when an anomaly is closed.</p>
    pub fn close_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.close_time.as_ref()
    }
}
impl AnomalyReportedTimeRange {
    /// Creates a new builder-style object to manufacture [`AnomalyReportedTimeRange`](crate::types::AnomalyReportedTimeRange).
    pub fn builder() -> crate::types::builders::AnomalyReportedTimeRangeBuilder {
        crate::types::builders::AnomalyReportedTimeRangeBuilder::default()
    }
}

/// A builder for [`AnomalyReportedTimeRange`](crate::types::AnomalyReportedTimeRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnomalyReportedTimeRangeBuilder {
    pub(crate) open_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) close_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AnomalyReportedTimeRangeBuilder {
    /// <p>The time when an anomaly is opened.</p>
    /// This field is required.
    pub fn open_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.open_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when an anomaly is opened.</p>
    pub fn set_open_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.open_time = input;
        self
    }
    /// <p>The time when an anomaly is opened.</p>
    pub fn get_open_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.open_time
    }
    /// <p>The time when an anomaly is closed.</p>
    pub fn close_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.close_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when an anomaly is closed.</p>
    pub fn set_close_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.close_time = input;
        self
    }
    /// <p>The time when an anomaly is closed.</p>
    pub fn get_close_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.close_time
    }
    /// Consumes the builder and constructs a [`AnomalyReportedTimeRange`](crate::types::AnomalyReportedTimeRange).
    /// This method will fail if any of the following fields are not set:
    /// - [`open_time`](crate::types::builders::AnomalyReportedTimeRangeBuilder::open_time)
    pub fn build(self) -> ::std::result::Result<crate::types::AnomalyReportedTimeRange, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnomalyReportedTimeRange {
            open_time: self.open_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "open_time",
                    "open_time was not specified but it is required when building AnomalyReportedTimeRange",
                )
            })?,
            close_time: self.close_time,
        })
    }
}
