// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOrganizationRecommendationResourcesOutput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of Recommendation Resources</p>
    pub organization_recommendation_resource_summaries: ::std::vec::Vec<crate::types::OrganizationRecommendationResourceSummary>,
    _request_id: Option<String>,
}
impl ListOrganizationRecommendationResourcesOutput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn organization_recommendation_resource_summaries(&self) -> &[crate::types::OrganizationRecommendationResourceSummary] {
        use std::ops::Deref;
        self.organization_recommendation_resource_summaries.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListOrganizationRecommendationResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListOrganizationRecommendationResourcesOutput {
    /// Creates a new builder-style object to manufacture [`ListOrganizationRecommendationResourcesOutput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesOutput).
    pub fn builder() -> crate::operation::list_organization_recommendation_resources::builders::ListOrganizationRecommendationResourcesOutputBuilder {
        crate::operation::list_organization_recommendation_resources::builders::ListOrganizationRecommendationResourcesOutputBuilder::default()
    }
}

/// A builder for [`ListOrganizationRecommendationResourcesOutput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOrganizationRecommendationResourcesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) organization_recommendation_resource_summaries:
        ::std::option::Option<::std::vec::Vec<crate::types::OrganizationRecommendationResourceSummary>>,
    _request_id: Option<String>,
}
impl ListOrganizationRecommendationResourcesOutputBuilder {
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
    /// Appends an item to `organization_recommendation_resource_summaries`.
    ///
    /// To override the contents of this collection use [`set_organization_recommendation_resource_summaries`](Self::set_organization_recommendation_resource_summaries).
    ///
    /// <p>A list of Recommendation Resources</p>
    pub fn organization_recommendation_resource_summaries(mut self, input: crate::types::OrganizationRecommendationResourceSummary) -> Self {
        let mut v = self.organization_recommendation_resource_summaries.unwrap_or_default();
        v.push(input);
        self.organization_recommendation_resource_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn set_organization_recommendation_resource_summaries(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::OrganizationRecommendationResourceSummary>>,
    ) -> Self {
        self.organization_recommendation_resource_summaries = input;
        self
    }
    /// <p>A list of Recommendation Resources</p>
    pub fn get_organization_recommendation_resource_summaries(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::OrganizationRecommendationResourceSummary>> {
        &self.organization_recommendation_resource_summaries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListOrganizationRecommendationResourcesOutput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`organization_recommendation_resource_summaries`](crate::operation::list_organization_recommendation_resources::builders::ListOrganizationRecommendationResourcesOutputBuilder::organization_recommendation_resource_summaries)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesOutput {
                next_token: self.next_token
                ,
                organization_recommendation_resource_summaries: self.organization_recommendation_resource_summaries
                    .ok_or_else(||
                        ::aws_smithy_types::error::operation::BuildError::missing_field("organization_recommendation_resource_summaries", "organization_recommendation_resource_summaries was not specified but it is required when building ListOrganizationRecommendationResourcesOutput")
                    )?
                ,
                _request_id: self._request_id,
            }
        )
    }
}
