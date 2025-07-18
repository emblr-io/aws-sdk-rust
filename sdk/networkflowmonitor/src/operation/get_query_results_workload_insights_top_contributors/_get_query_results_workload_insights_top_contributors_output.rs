// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetQueryResultsWorkloadInsightsTopContributorsOutput {
    /// <p>The top contributor network flows overall for a specific metric type, for example, the number of retransmissions.</p>
    pub top_contributors: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsRow>>,
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsWorkloadInsightsTopContributorsOutput {
    /// <p>The top contributor network flows overall for a specific metric type, for example, the number of retransmissions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.top_contributors.is_none()`.
    pub fn top_contributors(&self) -> &[crate::types::WorkloadInsightsTopContributorsRow] {
        self.top_contributors.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results. You receive this token from a previous call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetQueryResultsWorkloadInsightsTopContributorsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetQueryResultsWorkloadInsightsTopContributorsOutput {
    /// Creates a new builder-style object to manufacture [`GetQueryResultsWorkloadInsightsTopContributorsOutput`](crate::operation::get_query_results_workload_insights_top_contributors::GetQueryResultsWorkloadInsightsTopContributorsOutput).
    pub fn builder(
    ) -> crate::operation::get_query_results_workload_insights_top_contributors::builders::GetQueryResultsWorkloadInsightsTopContributorsOutputBuilder
    {
        crate::operation::get_query_results_workload_insights_top_contributors::builders::GetQueryResultsWorkloadInsightsTopContributorsOutputBuilder::default()
    }
}

/// A builder for [`GetQueryResultsWorkloadInsightsTopContributorsOutput`](crate::operation::get_query_results_workload_insights_top_contributors::GetQueryResultsWorkloadInsightsTopContributorsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetQueryResultsWorkloadInsightsTopContributorsOutputBuilder {
    pub(crate) top_contributors: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsRow>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsWorkloadInsightsTopContributorsOutputBuilder {
    /// Appends an item to `top_contributors`.
    ///
    /// To override the contents of this collection use [`set_top_contributors`](Self::set_top_contributors).
    ///
    /// <p>The top contributor network flows overall for a specific metric type, for example, the number of retransmissions.</p>
    pub fn top_contributors(mut self, input: crate::types::WorkloadInsightsTopContributorsRow) -> Self {
        let mut v = self.top_contributors.unwrap_or_default();
        v.push(input);
        self.top_contributors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The top contributor network flows overall for a specific metric type, for example, the number of retransmissions.</p>
    pub fn set_top_contributors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsRow>>) -> Self {
        self.top_contributors = input;
        self
    }
    /// <p>The top contributor network flows overall for a specific metric type, for example, the number of retransmissions.</p>
    pub fn get_top_contributors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkloadInsightsTopContributorsRow>> {
        &self.top_contributors
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
    /// Consumes the builder and constructs a [`GetQueryResultsWorkloadInsightsTopContributorsOutput`](crate::operation::get_query_results_workload_insights_top_contributors::GetQueryResultsWorkloadInsightsTopContributorsOutput).
    pub fn build(
        self,
    ) -> crate::operation::get_query_results_workload_insights_top_contributors::GetQueryResultsWorkloadInsightsTopContributorsOutput {
        crate::operation::get_query_results_workload_insights_top_contributors::GetQueryResultsWorkloadInsightsTopContributorsOutput {
            top_contributors: self.top_contributors,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
