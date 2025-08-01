// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSessionsStatisticsAggregationInput {
    /// <p>The identifier of the farm to include in the statistics. This should be the same as the farm ID used in the call to the <code>StartSessionsStatisticsAggregation</code> operation.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier returned by the <code>StartSessionsStatisticsAggregation</code> operation that identifies the aggregated statistics.</p>
    pub aggregation_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetSessionsStatisticsAggregationInput {
    /// <p>The identifier of the farm to include in the statistics. This should be the same as the farm ID used in the call to the <code>StartSessionsStatisticsAggregation</code> operation.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The identifier returned by the <code>StartSessionsStatisticsAggregation</code> operation that identifies the aggregated statistics.</p>
    pub fn aggregation_id(&self) -> ::std::option::Option<&str> {
        self.aggregation_id.as_deref()
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetSessionsStatisticsAggregationInput {
    /// Creates a new builder-style object to manufacture [`GetSessionsStatisticsAggregationInput`](crate::operation::get_sessions_statistics_aggregation::GetSessionsStatisticsAggregationInput).
    pub fn builder() -> crate::operation::get_sessions_statistics_aggregation::builders::GetSessionsStatisticsAggregationInputBuilder {
        crate::operation::get_sessions_statistics_aggregation::builders::GetSessionsStatisticsAggregationInputBuilder::default()
    }
}

/// A builder for [`GetSessionsStatisticsAggregationInput`](crate::operation::get_sessions_statistics_aggregation::GetSessionsStatisticsAggregationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSessionsStatisticsAggregationInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) aggregation_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetSessionsStatisticsAggregationInputBuilder {
    /// <p>The identifier of the farm to include in the statistics. This should be the same as the farm ID used in the call to the <code>StartSessionsStatisticsAggregation</code> operation.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the farm to include in the statistics. This should be the same as the farm ID used in the call to the <code>StartSessionsStatisticsAggregation</code> operation.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The identifier of the farm to include in the statistics. This should be the same as the farm ID used in the call to the <code>StartSessionsStatisticsAggregation</code> operation.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The identifier returned by the <code>StartSessionsStatisticsAggregation</code> operation that identifies the aggregated statistics.</p>
    /// This field is required.
    pub fn aggregation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aggregation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier returned by the <code>StartSessionsStatisticsAggregation</code> operation that identifies the aggregated statistics.</p>
    pub fn set_aggregation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aggregation_id = input;
        self
    }
    /// <p>The identifier returned by the <code>StartSessionsStatisticsAggregation</code> operation that identifies the aggregated statistics.</p>
    pub fn get_aggregation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aggregation_id
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetSessionsStatisticsAggregationInput`](crate::operation::get_sessions_statistics_aggregation::GetSessionsStatisticsAggregationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_sessions_statistics_aggregation::GetSessionsStatisticsAggregationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_sessions_statistics_aggregation::GetSessionsStatisticsAggregationInput {
                farm_id: self.farm_id,
                aggregation_id: self.aggregation_id,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
