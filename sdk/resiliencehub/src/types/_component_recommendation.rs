// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines recommendations for an Resilience Hub Application Component, returned as an object. This object contains component names, configuration recommendations, and recommendation statuses.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ComponentRecommendation {
    /// <p>Name of the Application Component.</p>
    pub app_component_name: ::std::string::String,
    /// <p>Status of the recommendation.</p>
    pub recommendation_status: crate::types::RecommendationComplianceStatus,
    /// <p>List of recommendations.</p>
    pub config_recommendations: ::std::vec::Vec<crate::types::ConfigRecommendation>,
}
impl ComponentRecommendation {
    /// <p>Name of the Application Component.</p>
    pub fn app_component_name(&self) -> &str {
        use std::ops::Deref;
        self.app_component_name.deref()
    }
    /// <p>Status of the recommendation.</p>
    pub fn recommendation_status(&self) -> &crate::types::RecommendationComplianceStatus {
        &self.recommendation_status
    }
    /// <p>List of recommendations.</p>
    pub fn config_recommendations(&self) -> &[crate::types::ConfigRecommendation] {
        use std::ops::Deref;
        self.config_recommendations.deref()
    }
}
impl ComponentRecommendation {
    /// Creates a new builder-style object to manufacture [`ComponentRecommendation`](crate::types::ComponentRecommendation).
    pub fn builder() -> crate::types::builders::ComponentRecommendationBuilder {
        crate::types::builders::ComponentRecommendationBuilder::default()
    }
}

/// A builder for [`ComponentRecommendation`](crate::types::ComponentRecommendation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ComponentRecommendationBuilder {
    pub(crate) app_component_name: ::std::option::Option<::std::string::String>,
    pub(crate) recommendation_status: ::std::option::Option<crate::types::RecommendationComplianceStatus>,
    pub(crate) config_recommendations: ::std::option::Option<::std::vec::Vec<crate::types::ConfigRecommendation>>,
}
impl ComponentRecommendationBuilder {
    /// <p>Name of the Application Component.</p>
    /// This field is required.
    pub fn app_component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the Application Component.</p>
    pub fn set_app_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_component_name = input;
        self
    }
    /// <p>Name of the Application Component.</p>
    pub fn get_app_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_component_name
    }
    /// <p>Status of the recommendation.</p>
    /// This field is required.
    pub fn recommendation_status(mut self, input: crate::types::RecommendationComplianceStatus) -> Self {
        self.recommendation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the recommendation.</p>
    pub fn set_recommendation_status(mut self, input: ::std::option::Option<crate::types::RecommendationComplianceStatus>) -> Self {
        self.recommendation_status = input;
        self
    }
    /// <p>Status of the recommendation.</p>
    pub fn get_recommendation_status(&self) -> &::std::option::Option<crate::types::RecommendationComplianceStatus> {
        &self.recommendation_status
    }
    /// Appends an item to `config_recommendations`.
    ///
    /// To override the contents of this collection use [`set_config_recommendations`](Self::set_config_recommendations).
    ///
    /// <p>List of recommendations.</p>
    pub fn config_recommendations(mut self, input: crate::types::ConfigRecommendation) -> Self {
        let mut v = self.config_recommendations.unwrap_or_default();
        v.push(input);
        self.config_recommendations = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of recommendations.</p>
    pub fn set_config_recommendations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConfigRecommendation>>) -> Self {
        self.config_recommendations = input;
        self
    }
    /// <p>List of recommendations.</p>
    pub fn get_config_recommendations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConfigRecommendation>> {
        &self.config_recommendations
    }
    /// Consumes the builder and constructs a [`ComponentRecommendation`](crate::types::ComponentRecommendation).
    /// This method will fail if any of the following fields are not set:
    /// - [`app_component_name`](crate::types::builders::ComponentRecommendationBuilder::app_component_name)
    /// - [`recommendation_status`](crate::types::builders::ComponentRecommendationBuilder::recommendation_status)
    /// - [`config_recommendations`](crate::types::builders::ComponentRecommendationBuilder::config_recommendations)
    pub fn build(self) -> ::std::result::Result<crate::types::ComponentRecommendation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ComponentRecommendation {
            app_component_name: self.app_component_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_component_name",
                    "app_component_name was not specified but it is required when building ComponentRecommendation",
                )
            })?,
            recommendation_status: self.recommendation_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recommendation_status",
                    "recommendation_status was not specified but it is required when building ComponentRecommendation",
                )
            })?,
            config_recommendations: self.config_recommendations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "config_recommendations",
                    "config_recommendations was not specified but it is required when building ComponentRecommendation",
                )
            })?,
        })
    }
}
