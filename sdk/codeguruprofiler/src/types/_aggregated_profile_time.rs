// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the aggregation period and aggregation start time for an aggregated profile. An aggregated profile is used to collect posted agent profiles during an aggregation period. There are three possible aggregation periods (1 day, 1 hour, or 5 minutes).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AggregatedProfileTime {
    /// <p>The time that aggregation of posted agent profiles for a profiling group starts. The aggregation profile contains profiles posted by the agent starting at this time for an aggregation period specified by the <code>period</code> property of the <code>AggregatedProfileTime</code> object.</p>
    /// <p>Specify <code>start</code> using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub start: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The aggregation period. This indicates the period during which an aggregation profile collects posted agent profiles for a profiling group. Use one of three valid durations that are specified using the ISO 8601 format.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub period: ::std::option::Option<crate::types::AggregationPeriod>,
}
impl AggregatedProfileTime {
    /// <p>The time that aggregation of posted agent profiles for a profiling group starts. The aggregation profile contains profiles posted by the agent starting at this time for an aggregation period specified by the <code>period</code> property of the <code>AggregatedProfileTime</code> object.</p>
    /// <p>Specify <code>start</code> using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn start(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start.as_ref()
    }
    /// <p>The aggregation period. This indicates the period during which an aggregation profile collects posted agent profiles for a profiling group. Use one of three valid durations that are specified using the ISO 8601 format.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn period(&self) -> ::std::option::Option<&crate::types::AggregationPeriod> {
        self.period.as_ref()
    }
}
impl AggregatedProfileTime {
    /// Creates a new builder-style object to manufacture [`AggregatedProfileTime`](crate::types::AggregatedProfileTime).
    pub fn builder() -> crate::types::builders::AggregatedProfileTimeBuilder {
        crate::types::builders::AggregatedProfileTimeBuilder::default()
    }
}

/// A builder for [`AggregatedProfileTime`](crate::types::AggregatedProfileTime).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AggregatedProfileTimeBuilder {
    pub(crate) start: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) period: ::std::option::Option<crate::types::AggregationPeriod>,
}
impl AggregatedProfileTimeBuilder {
    /// <p>The time that aggregation of posted agent profiles for a profiling group starts. The aggregation profile contains profiles posted by the agent starting at this time for an aggregation period specified by the <code>period</code> property of the <code>AggregatedProfileTime</code> object.</p>
    /// <p>Specify <code>start</code> using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn start(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that aggregation of posted agent profiles for a profiling group starts. The aggregation profile contains profiles posted by the agent starting at this time for an aggregation period specified by the <code>period</code> property of the <code>AggregatedProfileTime</code> object.</p>
    /// <p>Specify <code>start</code> using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_start(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start = input;
        self
    }
    /// <p>The time that aggregation of posted agent profiles for a profiling group starts. The aggregation profile contains profiles posted by the agent starting at this time for an aggregation period specified by the <code>period</code> property of the <code>AggregatedProfileTime</code> object.</p>
    /// <p>Specify <code>start</code> using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_start(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start
    }
    /// <p>The aggregation period. This indicates the period during which an aggregation profile collects posted agent profiles for a profiling group. Use one of three valid durations that are specified using the ISO 8601 format.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn period(mut self, input: crate::types::AggregationPeriod) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregation period. This indicates the period during which an aggregation profile collects posted agent profiles for a profiling group. Use one of three valid durations that are specified using the ISO 8601 format.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn set_period(mut self, input: ::std::option::Option<crate::types::AggregationPeriod>) -> Self {
        self.period = input;
        self
    }
    /// <p>The aggregation period. This indicates the period during which an aggregation profile collects posted agent profiles for a profiling group. Use one of three valid durations that are specified using the ISO 8601 format.</p>
    /// <ul>
    /// <li>
    /// <p><code>P1D</code> — 1 day</p></li>
    /// <li>
    /// <p><code>PT1H</code> — 1 hour</p></li>
    /// <li>
    /// <p><code>PT5M</code> — 5 minutes</p></li>
    /// </ul>
    pub fn get_period(&self) -> &::std::option::Option<crate::types::AggregationPeriod> {
        &self.period
    }
    /// Consumes the builder and constructs a [`AggregatedProfileTime`](crate::types::AggregatedProfileTime).
    pub fn build(self) -> crate::types::AggregatedProfileTime {
        crate::types::AggregatedProfileTime {
            start: self.start,
            period: self.period,
        }
    }
}
