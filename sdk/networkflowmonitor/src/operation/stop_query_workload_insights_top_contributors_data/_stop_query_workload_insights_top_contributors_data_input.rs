// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopQueryWorkloadInsightsTopContributorsDataInput {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub scope_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to create a query.</p>
    pub query_id: ::std::option::Option<::std::string::String>,
}
impl StopQueryWorkloadInsightsTopContributorsDataInput {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn scope_id(&self) -> ::std::option::Option<&str> {
        self.scope_id.as_deref()
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to create a query.</p>
    pub fn query_id(&self) -> ::std::option::Option<&str> {
        self.query_id.as_deref()
    }
}
impl StopQueryWorkloadInsightsTopContributorsDataInput {
    /// Creates a new builder-style object to manufacture [`StopQueryWorkloadInsightsTopContributorsDataInput`](crate::operation::stop_query_workload_insights_top_contributors_data::StopQueryWorkloadInsightsTopContributorsDataInput).
    pub fn builder(
    ) -> crate::operation::stop_query_workload_insights_top_contributors_data::builders::StopQueryWorkloadInsightsTopContributorsDataInputBuilder
    {
        crate::operation::stop_query_workload_insights_top_contributors_data::builders::StopQueryWorkloadInsightsTopContributorsDataInputBuilder::default()
    }
}

/// A builder for [`StopQueryWorkloadInsightsTopContributorsDataInput`](crate::operation::stop_query_workload_insights_top_contributors_data::StopQueryWorkloadInsightsTopContributorsDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopQueryWorkloadInsightsTopContributorsDataInputBuilder {
    pub(crate) scope_id: ::std::option::Option<::std::string::String>,
    pub(crate) query_id: ::std::option::Option<::std::string::String>,
}
impl StopQueryWorkloadInsightsTopContributorsDataInputBuilder {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    /// This field is required.
    pub fn scope_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn set_scope_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope_id = input;
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account.</p>
    pub fn get_scope_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope_id
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to create a query.</p>
    /// This field is required.
    pub fn query_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to create a query.</p>
    pub fn set_query_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_id = input;
        self
    }
    /// <p>The identifier for the query. A query ID is an internally-generated identifier for a specific query returned from an API call to create a query.</p>
    pub fn get_query_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_id
    }
    /// Consumes the builder and constructs a [`StopQueryWorkloadInsightsTopContributorsDataInput`](crate::operation::stop_query_workload_insights_top_contributors_data::StopQueryWorkloadInsightsTopContributorsDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_query_workload_insights_top_contributors_data::StopQueryWorkloadInsightsTopContributorsDataInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::stop_query_workload_insights_top_contributors_data::StopQueryWorkloadInsightsTopContributorsDataInput {
                scope_id: self.scope_id,
                query_id: self.query_id,
            },
        )
    }
}
