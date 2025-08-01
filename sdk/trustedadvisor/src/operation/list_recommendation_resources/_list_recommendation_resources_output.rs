// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRecommendationResourcesOutput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of Recommendation Resources</p>
    pub recommendation_resource_summaries: ::std::vec::Vec<crate::types::RecommendationResourceSummary>,
    _request_id: Option<String>,
}
impl ListRecommendationResourcesOutput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn recommendation_resource_summaries(&self) -> &[crate::types::RecommendationResourceSummary] {
        use std::ops::Deref;
        self.recommendation_resource_summaries.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRecommendationResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRecommendationResourcesOutput {
    /// Creates a new builder-style object to manufacture [`ListRecommendationResourcesOutput`](crate::operation::list_recommendation_resources::ListRecommendationResourcesOutput).
    pub fn builder() -> crate::operation::list_recommendation_resources::builders::ListRecommendationResourcesOutputBuilder {
        crate::operation::list_recommendation_resources::builders::ListRecommendationResourcesOutputBuilder::default()
    }
}

/// A builder for [`ListRecommendationResourcesOutput`](crate::operation::list_recommendation_resources::ListRecommendationResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRecommendationResourcesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_resource_summaries: ::std::option::Option<::std::vec::Vec<crate::types::RecommendationResourceSummary>>,
    _request_id: Option<String>,
}
impl ListRecommendationResourcesOutputBuilder {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `recommendation_resource_summaries`.
    ///
    /// To override the contents of this collection use [`set_recommendation_resource_summaries`](Self::set_recommendation_resource_summaries).
    ///
    /// <p>A list of Recommendation Resources</p>
    pub fn recommendation_resource_summaries(mut self, input: crate::types::RecommendationResourceSummary) -> Self {
        let mut v = self.recommendation_resource_summaries.unwrap_or_default();
        v.push(input);
        self.recommendation_resource_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn set_recommendation_resource_summaries(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::RecommendationResourceSummary>>,
    ) -> Self {
        self.recommendation_resource_summaries = input;
        self
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn get_recommendation_resource_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecommendationResourceSummary>> {
        &self.recommendation_resource_summaries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListRecommendationResourcesOutput`](crate::operation::list_recommendation_resources::ListRecommendationResourcesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`recommendation_resource_summaries`](crate::operation::list_recommendation_resources::builders::ListRecommendationResourcesOutputBuilder::recommendation_resource_summaries)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_recommendation_resources::ListRecommendationResourcesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_recommendation_resources::ListRecommendationResourcesOutput {
            next_token: self.next_token,
            recommendation_resource_summaries: self.recommendation_resource_summaries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recommendation_resource_summaries",
                    "recommendation_resource_summaries was not specified but it is required when building ListRecommendationResourcesOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
