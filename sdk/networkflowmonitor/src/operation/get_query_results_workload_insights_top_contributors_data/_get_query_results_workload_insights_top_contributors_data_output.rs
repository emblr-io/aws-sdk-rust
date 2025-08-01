// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetQueryResultsWorkloadInsightsTopContributorsDataOutput {
    /// <p>The units for a metric returned by the query.</p>
    pub unit: crate::types::MetricUnit,
    /// <p>The datapoints returned by the query.</p>
    pub datapoints: ::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsDataPoint>,
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsWorkloadInsightsTopContributorsDataOutput {
    /// <p>The units for a metric returned by the query.</p>
    pub fn unit(&self) -> &crate::types::MetricUnit {
        &self.unit
    }
    /// <p>The datapoints returned by the query.</p>
    pub fn datapoints(&self) -> &[crate::types::WorkloadInsightsTopContributorsDataPoint] {
        use std::ops::Deref;
        self.datapoints.deref()
    }
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetQueryResultsWorkloadInsightsTopContributorsDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetQueryResultsWorkloadInsightsTopContributorsDataOutput {
    /// Creates a new builder-style object to manufacture [`GetQueryResultsWorkloadInsightsTopContributorsDataOutput`](crate::operation::get_query_results_workload_insights_top_contributors_data::GetQueryResultsWorkloadInsightsTopContributorsDataOutput).
    pub fn builder() -> crate::operation::get_query_results_workload_insights_top_contributors_data::builders::GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder{
        crate::operation::get_query_results_workload_insights_top_contributors_data::builders::GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder::default()
    }
}

/// A builder for [`GetQueryResultsWorkloadInsightsTopContributorsDataOutput`](crate::operation::get_query_results_workload_insights_top_contributors_data::GetQueryResultsWorkloadInsightsTopContributorsDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder {
    pub(crate) unit: ::std::option::Option<crate::types::MetricUnit>,
    pub(crate) datapoints: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsDataPoint>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder {
    /// <p>The units for a metric returned by the query.</p>
    /// This field is required.
    pub fn unit(mut self, input: crate::types::MetricUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The units for a metric returned by the query.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::MetricUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The units for a metric returned by the query.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::MetricUnit> {
        &self.unit
    }
    /// Appends an item to `datapoints`.
    ///
    /// To override the contents of this collection use [`set_datapoints`](Self::set_datapoints).
    ///
    /// <p>The datapoints returned by the query.</p>
    pub fn datapoints(mut self, input: crate::types::WorkloadInsightsTopContributorsDataPoint) -> Self {
        let mut v = self.datapoints.unwrap_or_default();
        v.push(input);
        self.datapoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>The datapoints returned by the query.</p>
    pub fn set_datapoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsDataPoint>>) -> Self {
        self.datapoints = input;
        self
    }
    /// <p>The datapoints returned by the query.</p>
    pub fn get_datapoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsDataPoint>> {
        &self.datapoints
    }
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetQueryResultsWorkloadInsightsTopContributorsDataOutput`](crate::operation::get_query_results_workload_insights_top_contributors_data::GetQueryResultsWorkloadInsightsTopContributorsDataOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`unit`](crate::operation::get_query_results_workload_insights_top_contributors_data::builders::GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder::unit)
    /// - [`datapoints`](crate::operation::get_query_results_workload_insights_top_contributors_data::builders::GetQueryResultsWorkloadInsightsTopContributorsDataOutputBuilder::datapoints)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_query_results_workload_insights_top_contributors_data::GetQueryResultsWorkloadInsightsTopContributorsDataOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_query_results_workload_insights_top_contributors_data::GetQueryResultsWorkloadInsightsTopContributorsDataOutput {
                unit: self.unit.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "unit",
                        "unit was not specified but it is required when building GetQueryResultsWorkloadInsightsTopContributorsDataOutput",
                    )
                })?,
                datapoints: self.datapoints.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "datapoints",
                        "datapoints was not specified but it is required when building GetQueryResultsWorkloadInsightsTopContributorsDataOutput",
                    )
                })?,
                next_token: self.next_token,
                _request_id: self._request_id,
            },
        )
    }
}
