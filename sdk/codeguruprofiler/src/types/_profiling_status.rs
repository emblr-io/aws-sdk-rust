// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Profiling status includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProfilingStatus {
    /// <p>The date and time when the most recent profile was received. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub latest_agent_profile_reported_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AggregatedProfileTime.html"> <code>AggregatedProfileTime</code> </a> object that contains the aggregation period and start time for an aggregated profile.</p>
    pub latest_aggregated_profile: ::std::option::Option<crate::types::AggregatedProfileTime>,
    /// <p>The date and time when the profiling agent most recently pinged back. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub latest_agent_orchestrated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ProfilingStatus {
    /// <p>The date and time when the most recent profile was received. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn latest_agent_profile_reported_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.latest_agent_profile_reported_at.as_ref()
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AggregatedProfileTime.html"> <code>AggregatedProfileTime</code> </a> object that contains the aggregation period and start time for an aggregated profile.</p>
    pub fn latest_aggregated_profile(&self) -> ::std::option::Option<&crate::types::AggregatedProfileTime> {
        self.latest_aggregated_profile.as_ref()
    }
    /// <p>The date and time when the profiling agent most recently pinged back. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn latest_agent_orchestrated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.latest_agent_orchestrated_at.as_ref()
    }
}
impl ProfilingStatus {
    /// Creates a new builder-style object to manufacture [`ProfilingStatus`](crate::types::ProfilingStatus).
    pub fn builder() -> crate::types::builders::ProfilingStatusBuilder {
        crate::types::builders::ProfilingStatusBuilder::default()
    }
}

/// A builder for [`ProfilingStatus`](crate::types::ProfilingStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProfilingStatusBuilder {
    pub(crate) latest_agent_profile_reported_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) latest_aggregated_profile: ::std::option::Option<crate::types::AggregatedProfileTime>,
    pub(crate) latest_agent_orchestrated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ProfilingStatusBuilder {
    /// <p>The date and time when the most recent profile was received. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn latest_agent_profile_reported_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.latest_agent_profile_reported_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the most recent profile was received. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_latest_agent_profile_reported_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.latest_agent_profile_reported_at = input;
        self
    }
    /// <p>The date and time when the most recent profile was received. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_latest_agent_profile_reported_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.latest_agent_profile_reported_at
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AggregatedProfileTime.html"> <code>AggregatedProfileTime</code> </a> object that contains the aggregation period and start time for an aggregated profile.</p>
    pub fn latest_aggregated_profile(mut self, input: crate::types::AggregatedProfileTime) -> Self {
        self.latest_aggregated_profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AggregatedProfileTime.html"> <code>AggregatedProfileTime</code> </a> object that contains the aggregation period and start time for an aggregated profile.</p>
    pub fn set_latest_aggregated_profile(mut self, input: ::std::option::Option<crate::types::AggregatedProfileTime>) -> Self {
        self.latest_aggregated_profile = input;
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AggregatedProfileTime.html"> <code>AggregatedProfileTime</code> </a> object that contains the aggregation period and start time for an aggregated profile.</p>
    pub fn get_latest_aggregated_profile(&self) -> &::std::option::Option<crate::types::AggregatedProfileTime> {
        &self.latest_aggregated_profile
    }
    /// <p>The date and time when the profiling agent most recently pinged back. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn latest_agent_orchestrated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.latest_agent_orchestrated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the profiling agent most recently pinged back. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_latest_agent_orchestrated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.latest_agent_orchestrated_at = input;
        self
    }
    /// <p>The date and time when the profiling agent most recently pinged back. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_latest_agent_orchestrated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.latest_agent_orchestrated_at
    }
    /// Consumes the builder and constructs a [`ProfilingStatus`](crate::types::ProfilingStatus).
    pub fn build(self) -> crate::types::ProfilingStatus {
        crate::types::ProfilingStatus {
            latest_agent_profile_reported_at: self.latest_agent_profile_reported_at,
            latest_aggregated_profile: self.latest_aggregated_profile,
            latest_agent_orchestrated_at: self.latest_agent_orchestrated_at,
        }
    }
}
