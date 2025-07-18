// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateOrganizationRecommendationLifecycleInput {
    /// <p>The new lifecycle stage</p>
    pub lifecycle_stage: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStage>,
    /// <p>Reason for the lifecycle stage change</p>
    pub update_reason: ::std::option::Option<::std::string::String>,
    /// <p>Reason code for the lifecycle state change</p>
    pub update_reason_code: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStageReasonCode>,
    /// <p>The Recommendation identifier for AWS Trusted Advisor Priority recommendations</p>
    pub organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
}
impl UpdateOrganizationRecommendationLifecycleInput {
    /// <p>The new lifecycle stage</p>
    pub fn lifecycle_stage(&self) -> ::std::option::Option<&crate::types::UpdateRecommendationLifecycleStage> {
        self.lifecycle_stage.as_ref()
    }
    /// <p>Reason for the lifecycle stage change</p>
    pub fn update_reason(&self) -> ::std::option::Option<&str> {
        self.update_reason.as_deref()
    }
    /// <p>Reason code for the lifecycle state change</p>
    pub fn update_reason_code(&self) -> ::std::option::Option<&crate::types::UpdateRecommendationLifecycleStageReasonCode> {
        self.update_reason_code.as_ref()
    }
    /// <p>The Recommendation identifier for AWS Trusted Advisor Priority recommendations</p>
    pub fn organization_recommendation_identifier(&self) -> ::std::option::Option<&str> {
        self.organization_recommendation_identifier.as_deref()
    }
}
impl ::std::fmt::Debug for UpdateOrganizationRecommendationLifecycleInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateOrganizationRecommendationLifecycleInput");
        formatter.field("lifecycle_stage", &self.lifecycle_stage);
        formatter.field("update_reason", &"*** Sensitive Data Redacted ***");
        formatter.field("update_reason_code", &self.update_reason_code);
        formatter.field("organization_recommendation_identifier", &self.organization_recommendation_identifier);
        formatter.finish()
    }
}
impl UpdateOrganizationRecommendationLifecycleInput {
    /// Creates a new builder-style object to manufacture [`UpdateOrganizationRecommendationLifecycleInput`](crate::operation::update_organization_recommendation_lifecycle::UpdateOrganizationRecommendationLifecycleInput).
    pub fn builder() -> crate::operation::update_organization_recommendation_lifecycle::builders::UpdateOrganizationRecommendationLifecycleInputBuilder
    {
        crate::operation::update_organization_recommendation_lifecycle::builders::UpdateOrganizationRecommendationLifecycleInputBuilder::default()
    }
}

/// A builder for [`UpdateOrganizationRecommendationLifecycleInput`](crate::operation::update_organization_recommendation_lifecycle::UpdateOrganizationRecommendationLifecycleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateOrganizationRecommendationLifecycleInputBuilder {
    pub(crate) lifecycle_stage: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStage>,
    pub(crate) update_reason: ::std::option::Option<::std::string::String>,
    pub(crate) update_reason_code: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStageReasonCode>,
    pub(crate) organization_recommendation_identifier: ::std::option::Option<::std::string::String>,
}
impl UpdateOrganizationRecommendationLifecycleInputBuilder {
    /// <p>The new lifecycle stage</p>
    /// This field is required.
    pub fn lifecycle_stage(mut self, input: crate::types::UpdateRecommendationLifecycleStage) -> Self {
        self.lifecycle_stage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new lifecycle stage</p>
    pub fn set_lifecycle_stage(mut self, input: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStage>) -> Self {
        self.lifecycle_stage = input;
        self
    }
    /// <p>The new lifecycle stage</p>
    pub fn get_lifecycle_stage(&self) -> &::std::option::Option<crate::types::UpdateRecommendationLifecycleStage> {
        &self.lifecycle_stage
    }
    /// <p>Reason for the lifecycle stage change</p>
    pub fn update_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.update_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reason for the lifecycle stage change</p>
    pub fn set_update_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.update_reason = input;
        self
    }
    /// <p>Reason for the lifecycle stage change</p>
    pub fn get_update_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.update_reason
    }
    /// <p>Reason code for the lifecycle state change</p>
    pub fn update_reason_code(mut self, input: crate::types::UpdateRecommendationLifecycleStageReasonCode) -> Self {
        self.update_reason_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reason code for the lifecycle state change</p>
    pub fn set_update_reason_code(mut self, input: ::std::option::Option<crate::types::UpdateRecommendationLifecycleStageReasonCode>) -> Self {
        self.update_reason_code = input;
        self
    }
    /// <p>Reason code for the lifecycle state change</p>
    pub fn get_update_reason_code(&self) -> &::std::option::Option<crate::types::UpdateRecommendationLifecycleStageReasonCode> {
        &self.update_reason_code
    }
    /// <p>The Recommendation identifier for AWS Trusted Advisor Priority recommendations</p>
    /// This field is required.
    pub fn organization_recommendation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Recommendation identifier for AWS Trusted Advisor Priority recommendations</p>
    pub fn set_organization_recommendation_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_recommendation_identifier = input;
        self
    }
    /// <p>The Recommendation identifier for AWS Trusted Advisor Priority recommendations</p>
    pub fn get_organization_recommendation_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_recommendation_identifier
    }
    /// Consumes the builder and constructs a [`UpdateOrganizationRecommendationLifecycleInput`](crate::operation::update_organization_recommendation_lifecycle::UpdateOrganizationRecommendationLifecycleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_organization_recommendation_lifecycle::UpdateOrganizationRecommendationLifecycleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_organization_recommendation_lifecycle::UpdateOrganizationRecommendationLifecycleInput {
                lifecycle_stage: self.lifecycle_stage,
                update_reason: self.update_reason,
                update_reason_code: self.update_reason_code,
                organization_recommendation_identifier: self.organization_recommendation_identifier,
            },
        )
    }
}
impl ::std::fmt::Debug for UpdateOrganizationRecommendationLifecycleInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateOrganizationRecommendationLifecycleInputBuilder");
        formatter.field("lifecycle_stage", &self.lifecycle_stage);
        formatter.field("update_reason", &"*** Sensitive Data Redacted ***");
        formatter.field("update_reason_code", &self.update_reason_code);
        formatter.field("organization_recommendation_identifier", &self.organization_recommendation_identifier);
        formatter.finish()
    }
}
