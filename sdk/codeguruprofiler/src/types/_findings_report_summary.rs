// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about potential recommendations that might be created from the analysis of profiling data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FindingsReportSummary {
    /// <p>The universally unique identifier (UUID) of the recommendation report.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the profiling group that is associated with the analysis data.</p>
    pub profiling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The start time of the profile the analysis data is about. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub profile_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end time of the period during which the metric is flagged as anomalous. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub profile_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The total number of different recommendations that were found by the analysis.</p>
    pub total_number_of_findings: ::std::option::Option<i32>,
}
impl FindingsReportSummary {
    /// <p>The universally unique identifier (UUID) of the recommendation report.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the profiling group that is associated with the analysis data.</p>
    pub fn profiling_group_name(&self) -> ::std::option::Option<&str> {
        self.profiling_group_name.as_deref()
    }
    /// <p>The start time of the profile the analysis data is about. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn profile_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.profile_start_time.as_ref()
    }
    /// <p>The end time of the period during which the metric is flagged as anomalous. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn profile_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.profile_end_time.as_ref()
    }
    /// <p>The total number of different recommendations that were found by the analysis.</p>
    pub fn total_number_of_findings(&self) -> ::std::option::Option<i32> {
        self.total_number_of_findings
    }
}
impl FindingsReportSummary {
    /// Creates a new builder-style object to manufacture [`FindingsReportSummary`](crate::types::FindingsReportSummary).
    pub fn builder() -> crate::types::builders::FindingsReportSummaryBuilder {
        crate::types::builders::FindingsReportSummaryBuilder::default()
    }
}

/// A builder for [`FindingsReportSummary`](crate::types::FindingsReportSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FindingsReportSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) profiling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) profile_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) profile_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) total_number_of_findings: ::std::option::Option<i32>,
}
impl FindingsReportSummaryBuilder {
    /// <p>The universally unique identifier (UUID) of the recommendation report.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The universally unique identifier (UUID) of the recommendation report.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The universally unique identifier (UUID) of the recommendation report.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the profiling group that is associated with the analysis data.</p>
    pub fn profiling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profiling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the profiling group that is associated with the analysis data.</p>
    pub fn set_profiling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profiling_group_name = input;
        self
    }
    /// <p>The name of the profiling group that is associated with the analysis data.</p>
    pub fn get_profiling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.profiling_group_name
    }
    /// <p>The start time of the profile the analysis data is about. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn profile_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.profile_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of the profile the analysis data is about. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_profile_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.profile_start_time = input;
        self
    }
    /// <p>The start time of the profile the analysis data is about. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_profile_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.profile_start_time
    }
    /// <p>The end time of the period during which the metric is flagged as anomalous. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn profile_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.profile_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time of the period during which the metric is flagged as anomalous. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_profile_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.profile_end_time = input;
        self
    }
    /// <p>The end time of the period during which the metric is flagged as anomalous. This is specified using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_profile_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.profile_end_time
    }
    /// <p>The total number of different recommendations that were found by the analysis.</p>
    pub fn total_number_of_findings(mut self, input: i32) -> Self {
        self.total_number_of_findings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of different recommendations that were found by the analysis.</p>
    pub fn set_total_number_of_findings(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_number_of_findings = input;
        self
    }
    /// <p>The total number of different recommendations that were found by the analysis.</p>
    pub fn get_total_number_of_findings(&self) -> &::std::option::Option<i32> {
        &self.total_number_of_findings
    }
    /// Consumes the builder and constructs a [`FindingsReportSummary`](crate::types::FindingsReportSummary).
    pub fn build(self) -> crate::types::FindingsReportSummary {
        crate::types::FindingsReportSummary {
            id: self.id,
            profiling_group_name: self.profiling_group_name,
            profile_start_time: self.profile_start_time,
            profile_end_time: self.profile_end_time,
            total_number_of_findings: self.total_number_of_findings,
        }
    }
}
