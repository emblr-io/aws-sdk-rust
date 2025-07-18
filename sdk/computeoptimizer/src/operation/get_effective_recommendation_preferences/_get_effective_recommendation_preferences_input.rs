// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEffectiveRecommendationPreferencesInput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which to confirm effective recommendation preferences. Only EC2 instance and Auto Scaling group ARNs are currently supported.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetEffectiveRecommendationPreferencesInput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which to confirm effective recommendation preferences. Only EC2 instance and Auto Scaling group ARNs are currently supported.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl GetEffectiveRecommendationPreferencesInput {
    /// Creates a new builder-style object to manufacture [`GetEffectiveRecommendationPreferencesInput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesInput).
    pub fn builder() -> crate::operation::get_effective_recommendation_preferences::builders::GetEffectiveRecommendationPreferencesInputBuilder {
        crate::operation::get_effective_recommendation_preferences::builders::GetEffectiveRecommendationPreferencesInputBuilder::default()
    }
}

/// A builder for [`GetEffectiveRecommendationPreferencesInput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEffectiveRecommendationPreferencesInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetEffectiveRecommendationPreferencesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the resource for which to confirm effective recommendation preferences. Only EC2 instance and Auto Scaling group ARNs are currently supported.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which to confirm effective recommendation preferences. Only EC2 instance and Auto Scaling group ARNs are currently supported.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which to confirm effective recommendation preferences. Only EC2 instance and Auto Scaling group ARNs are currently supported.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`GetEffectiveRecommendationPreferencesInput`](crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_effective_recommendation_preferences::GetEffectiveRecommendationPreferencesInput {
                resource_arn: self.resource_arn,
            },
        )
    }
}
