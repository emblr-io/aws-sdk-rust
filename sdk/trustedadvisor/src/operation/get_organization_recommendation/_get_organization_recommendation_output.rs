// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOrganizationRecommendationOutput {
    /// <p>The Recommendation</p>
    pub organization_recommendation: ::std::option::Option<crate::types::OrganizationRecommendation>,
    _request_id: Option<String>,
}
impl GetOrganizationRecommendationOutput {
    /// <p>The Recommendation</p>
    pub fn organization_recommendation(&self) -> ::std::option::Option<&crate::types::OrganizationRecommendation> {
        self.organization_recommendation.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetOrganizationRecommendationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetOrganizationRecommendationOutput {
    /// Creates a new builder-style object to manufacture [`GetOrganizationRecommendationOutput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationOutput).
    pub fn builder() -> crate::operation::get_organization_recommendation::builders::GetOrganizationRecommendationOutputBuilder {
        crate::operation::get_organization_recommendation::builders::GetOrganizationRecommendationOutputBuilder::default()
    }
}

/// A builder for [`GetOrganizationRecommendationOutput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOrganizationRecommendationOutputBuilder {
    pub(crate) organization_recommendation: ::std::option::Option<crate::types::OrganizationRecommendation>,
    _request_id: Option<String>,
}
impl GetOrganizationRecommendationOutputBuilder {
    /// <p>The Recommendation</p>
    pub fn organization_recommendation(mut self, input: crate::types::OrganizationRecommendation) -> Self {
        self.organization_recommendation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Recommendation</p>
    pub fn set_organization_recommendation(mut self, input: ::std::option::Option<crate::types::OrganizationRecommendation>) -> Self {
        self.organization_recommendation = input;
        self
    }
    /// <p>The Recommendation</p>
    pub fn get_organization_recommendation(&self) -> &::std::option::Option<crate::types::OrganizationRecommendation> {
        &self.organization_recommendation
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetOrganizationRecommendationOutput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationOutput).
    pub fn build(self) -> crate::operation::get_organization_recommendation::GetOrganizationRecommendationOutput {
        crate::operation::get_organization_recommendation::GetOrganizationRecommendationOutput {
            organization_recommendation: self.organization_recommendation,
            _request_id: self._request_id,
        }
    }
}
