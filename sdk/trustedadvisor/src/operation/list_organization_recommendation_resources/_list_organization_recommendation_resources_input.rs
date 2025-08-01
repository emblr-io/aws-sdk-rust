// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOrganizationRecommendationResourcesInput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return per page.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The status of the resource</p>
    pub status: ::std::option::Option<crate::types::ResourceStatus>,
    /// <p>The exclusion status of the resource</p>
    pub exclusion_status: ::std::option::Option<crate::types::ExclusionStatus>,
    /// <p>The AWS Region code of the resource</p>
    pub region_code: ::std::option::Option<::std::string::String>,
    /// <p>The AWS Organization organization's Recommendation identifier</p>
    pub organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
    /// <p>An account affected by this organization recommendation</p>
    pub affected_account_id: ::std::option::Option<::std::string::String>,
}
impl ListOrganizationRecommendationResourcesInput {
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The status of the resource</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceStatus> {
        self.status.as_ref()
    }
    /// <p>The exclusion status of the resource</p>
    pub fn exclusion_status(&self) -> ::std::option::Option<&crate::types::ExclusionStatus> {
        self.exclusion_status.as_ref()
    }
    /// <p>The AWS Region code of the resource</p>
    pub fn region_code(&self) -> ::std::option::Option<&str> {
        self.region_code.as_deref()
    }
    /// <p>The AWS Organization organization's Recommendation identifier</p>
    pub fn organization_recommendation_identifier(&self) -> ::std::option::Option<&str> {
        self.organization_recommendation_identifier.as_deref()
    }
    /// <p>An account affected by this organization recommendation</p>
    pub fn affected_account_id(&self) -> ::std::option::Option<&str> {
        self.affected_account_id.as_deref()
    }
}
impl ListOrganizationRecommendationResourcesInput {
    /// Creates a new builder-style object to manufacture [`ListOrganizationRecommendationResourcesInput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesInput).
    pub fn builder() -> crate::operation::list_organization_recommendation_resources::builders::ListOrganizationRecommendationResourcesInputBuilder {
        crate::operation::list_organization_recommendation_resources::builders::ListOrganizationRecommendationResourcesInputBuilder::default()
    }
}

/// A builder for [`ListOrganizationRecommendationResourcesInput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOrganizationRecommendationResourcesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceStatus>,
    pub(crate) exclusion_status: ::std::option::Option<crate::types::ExclusionStatus>,
    pub(crate) region_code: ::std::option::Option<::std::string::String>,
    pub(crate) organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) affected_account_id: ::std::option::Option<::std::string::String>,
}
impl ListOrganizationRecommendationResourcesInputBuilder {
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
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The status of the resource</p>
    pub fn status(mut self, input: crate::types::ResourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the resource</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ResourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the resource</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceStatus> {
        &self.status
    }
    /// <p>The exclusion status of the resource</p>
    pub fn exclusion_status(mut self, input: crate::types::ExclusionStatus) -> Self {
        self.exclusion_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exclusion status of the resource</p>
    pub fn set_exclusion_status(mut self, input: ::std::option::Option<crate::types::ExclusionStatus>) -> Self {
        self.exclusion_status = input;
        self
    }
    /// <p>The exclusion status of the resource</p>
    pub fn get_exclusion_status(&self) -> &::std::option::Option<crate::types::ExclusionStatus> {
        &self.exclusion_status
    }
    /// <p>The AWS Region code of the resource</p>
    pub fn region_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Region code of the resource</p>
    pub fn set_region_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region_code = input;
        self
    }
    /// <p>The AWS Region code of the resource</p>
    pub fn get_region_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.region_code
    }
    /// <p>The AWS Organization organization's Recommendation identifier</p>
    /// This field is required.
    pub fn organization_recommendation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Organization organization's Recommendation identifier</p>
    pub fn set_organization_recommendation_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = input;
        self
    }
    /// <p>The AWS Organization organization's Recommendation identifier</p>
    pub fn get_organization_recommendation_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_recommendation_identifier
    }
    /// <p>An account affected by this organization recommendation</p>
    pub fn affected_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.affected_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An account affected by this organization recommendation</p>
    pub fn set_affected_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.affected_account_id = input;
        self
    }
    /// <p>An account affected by this organization recommendation</p>
    pub fn get_affected_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.affected_account_id
    }
    /// Consumes the builder and constructs a [`ListOrganizationRecommendationResourcesInput`](crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_organization_recommendation_resources::ListOrganizationRecommendationResourcesInput {
                next_token: self.next_token,
                max_results: self.max_results,
                status: self.status,
                exclusion_status: self.exclusion_status,
                region_code: self.region_code,
                organization_recommendation_identifier: self.organization_recommendation_identifier,
                affected_account_id: self.affected_account_id,
            },
        )
    }
}
