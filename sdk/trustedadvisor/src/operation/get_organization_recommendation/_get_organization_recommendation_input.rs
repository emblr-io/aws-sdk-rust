// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOrganizationRecommendationInput {
    /// <p>The Recommendation identifier</p>
    pub organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
}
impl GetOrganizationRecommendationInput {
    /// <p>The Recommendation identifier</p>
    pub fn organization_recommendation_identifier(&self) -> ::std::option::Option<&str> {
        self.organization_recommendation_identifier.as_deref()
    }
}
impl GetOrganizationRecommendationInput {
    /// Creates a new builder-style object to manufacture [`GetOrganizationRecommendationInput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationInput).
    pub fn builder() -> crate::operation::get_organization_recommendation::builders::GetOrganizationRecommendationInputBuilder {
        crate::operation::get_organization_recommendation::builders::GetOrganizationRecommendationInputBuilder::default()
    }
}

/// A builder for [`GetOrganizationRecommendationInput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOrganizationRecommendationInputBuilder {
    pub(crate) organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
}
impl GetOrganizationRecommendationInputBuilder {
    /// <p>The Recommendation identifier</p>
    /// This field is required.
    pub fn organization_recommendation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Recommendation identifier</p>
    pub fn set_organization_recommendation_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = input;
        self
    }
    /// <p>The Recommendation identifier</p>
    pub fn get_organization_recommendation_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_recommendation_identifier
    }
    /// Consumes the builder and constructs a [`GetOrganizationRecommendationInput`](crate::operation::get_organization_recommendation::GetOrganizationRecommendationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_organization_recommendation::GetOrganizationRecommendationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_organization_recommendation::GetOrganizationRecommendationInput {
            organization_recommendation_identifier: self.organization_recommendation_identifier,
        })
    }
}
