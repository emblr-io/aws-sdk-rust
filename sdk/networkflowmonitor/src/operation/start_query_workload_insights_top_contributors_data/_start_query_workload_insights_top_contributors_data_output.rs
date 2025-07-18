// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartQueryWorkloadInsightsTopContributorsDataOutput {
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to start a query.</p>
    pub query_id: ::std::string::String,
    _request_id: Option<String>,
}
impl StartQueryWorkloadInsightsTopContributorsDataOutput {
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to start a query.</p>
    pub fn query_id(&self) -> &str {
        use std::ops::Deref;
        self.query_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for StartQueryWorkloadInsightsTopContributorsDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartQueryWorkloadInsightsTopContributorsDataOutput {
    /// Creates a new builder-style object to manufacture [`StartQueryWorkloadInsightsTopContributorsDataOutput`](crate::operation::start_query_workload_insights_top_contributors_data::StartQueryWorkloadInsightsTopContributorsDataOutput).
    pub fn builder(
    ) -> crate::operation::start_query_workload_insights_top_contributors_data::builders::StartQueryWorkloadInsightsTopContributorsDataOutputBuilder
    {
        crate::operation::start_query_workload_insights_top_contributors_data::builders::StartQueryWorkloadInsightsTopContributorsDataOutputBuilder::default()
    }
}

/// A builder for [`StartQueryWorkloadInsightsTopContributorsDataOutput`](crate::operation::start_query_workload_insights_top_contributors_data::StartQueryWorkloadInsightsTopContributorsDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartQueryWorkloadInsightsTopContributorsDataOutputBuilder {
    pub(crate) query_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartQueryWorkloadInsightsTopContributorsDataOutputBuilder {
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to start a query.</p>
    /// This field is required.
    pub fn query_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to start a query.</p>
    pub fn set_query_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_id = input;
        self
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to start a query.</p>
    pub fn get_query_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartQueryWorkloadInsightsTopContributorsDataOutput`](crate::operation::start_query_workload_insights_top_contributors_data::StartQueryWorkloadInsightsTopContributorsDataOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`query_id`](crate::operation::start_query_workload_insights_top_contributors_data::builders::StartQueryWorkloadInsightsTopContributorsDataOutputBuilder::query_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_query_workload_insights_top_contributors_data::StartQueryWorkloadInsightsTopContributorsDataOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::start_query_workload_insights_top_contributors_data::StartQueryWorkloadInsightsTopContributorsDataOutput {
                query_id: self.query_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "query_id",
                        "query_id was not specified but it is required when building StartQueryWorkloadInsightsTopContributorsDataOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
