// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details for the guardrails contextual grounding filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardrailContextualGroundingFilter {
    /// <p>The contextual grounding filter type.</p>
    pub r#type: crate::types::GuardrailContextualGroundingFilterType,
    /// <p>The threshold used by contextual grounding filter to determine whether the content is grounded or not.</p>
    pub threshold: f64,
    /// <p>The score generated by contextual grounding filter.</p>
    pub score: f64,
    /// <p>The action performed by the guardrails contextual grounding filter.</p>
    pub action: crate::types::GuardrailContextualGroundingPolicyAction,
    /// <p>Indicates whether content that fails the contextual grounding evaluation (grounding or relevance score less than the corresponding threshold) was detected.</p>
    pub detected: ::std::option::Option<bool>,
}
impl GuardrailContextualGroundingFilter {
    /// <p>The contextual grounding filter type.</p>
    pub fn r#type(&self) -> &crate::types::GuardrailContextualGroundingFilterType {
        &self.r#type
    }
    /// <p>The threshold used by contextual grounding filter to determine whether the content is grounded or not.</p>
    pub fn threshold(&self) -> f64 {
        self.threshold
    }
    /// <p>The score generated by contextual grounding filter.</p>
    pub fn score(&self) -> f64 {
        self.score
    }
    /// <p>The action performed by the guardrails contextual grounding filter.</p>
    pub fn action(&self) -> &crate::types::GuardrailContextualGroundingPolicyAction {
        &self.action
    }
    /// <p>Indicates whether content that fails the contextual grounding evaluation (grounding or relevance score less than the corresponding threshold) was detected.</p>
    pub fn detected(&self) -> ::std::option::Option<bool> {
        self.detected
    }
}
impl GuardrailContextualGroundingFilter {
    /// Creates a new builder-style object to manufacture [`GuardrailContextualGroundingFilter`](crate::types::GuardrailContextualGroundingFilter).
    pub fn builder() -> crate::types::builders::GuardrailContextualGroundingFilterBuilder {
        crate::types::builders::GuardrailContextualGroundingFilterBuilder::default()
    }
}

/// A builder for [`GuardrailContextualGroundingFilter`](crate::types::GuardrailContextualGroundingFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardrailContextualGroundingFilterBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::GuardrailContextualGroundingFilterType>,
    pub(crate) threshold: ::std::option::Option<f64>,
    pub(crate) score: ::std::option::Option<f64>,
    pub(crate) action: ::std::option::Option<crate::types::GuardrailContextualGroundingPolicyAction>,
    pub(crate) detected: ::std::option::Option<bool>,
}
impl GuardrailContextualGroundingFilterBuilder {
    /// <p>The contextual grounding filter type.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::GuardrailContextualGroundingFilterType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The contextual grounding filter type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::GuardrailContextualGroundingFilterType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The contextual grounding filter type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::GuardrailContextualGroundingFilterType> {
        &self.r#type
    }
    /// <p>The threshold used by contextual grounding filter to determine whether the content is grounded or not.</p>
    /// This field is required.
    pub fn threshold(mut self, input: f64) -> Self {
        self.threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The threshold used by contextual grounding filter to determine whether the content is grounded or not.</p>
    pub fn set_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.threshold = input;
        self
    }
    /// <p>The threshold used by contextual grounding filter to determine whether the content is grounded or not.</p>
    pub fn get_threshold(&self) -> &::std::option::Option<f64> {
        &self.threshold
    }
    /// <p>The score generated by contextual grounding filter.</p>
    /// This field is required.
    pub fn score(mut self, input: f64) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The score generated by contextual grounding filter.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.score = input;
        self
    }
    /// <p>The score generated by contextual grounding filter.</p>
    pub fn get_score(&self) -> &::std::option::Option<f64> {
        &self.score
    }
    /// <p>The action performed by the guardrails contextual grounding filter.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::GuardrailContextualGroundingPolicyAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action performed by the guardrails contextual grounding filter.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::GuardrailContextualGroundingPolicyAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action performed by the guardrails contextual grounding filter.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::GuardrailContextualGroundingPolicyAction> {
        &self.action
    }
    /// <p>Indicates whether content that fails the contextual grounding evaluation (grounding or relevance score less than the corresponding threshold) was detected.</p>
    pub fn detected(mut self, input: bool) -> Self {
        self.detected = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether content that fails the contextual grounding evaluation (grounding or relevance score less than the corresponding threshold) was detected.</p>
    pub fn set_detected(mut self, input: ::std::option::Option<bool>) -> Self {
        self.detected = input;
        self
    }
    /// <p>Indicates whether content that fails the contextual grounding evaluation (grounding or relevance score less than the corresponding threshold) was detected.</p>
    pub fn get_detected(&self) -> &::std::option::Option<bool> {
        &self.detected
    }
    /// Consumes the builder and constructs a [`GuardrailContextualGroundingFilter`](crate::types::GuardrailContextualGroundingFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::GuardrailContextualGroundingFilterBuilder::type)
    /// - [`threshold`](crate::types::builders::GuardrailContextualGroundingFilterBuilder::threshold)
    /// - [`score`](crate::types::builders::GuardrailContextualGroundingFilterBuilder::score)
    /// - [`action`](crate::types::builders::GuardrailContextualGroundingFilterBuilder::action)
    pub fn build(self) -> ::std::result::Result<crate::types::GuardrailContextualGroundingFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailContextualGroundingFilter {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building GuardrailContextualGroundingFilter",
                )
            })?,
            threshold: self.threshold.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "threshold",
                    "threshold was not specified but it is required when building GuardrailContextualGroundingFilter",
                )
            })?,
            score: self.score.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "score",
                    "score was not specified but it is required when building GuardrailContextualGroundingFilter",
                )
            })?,
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building GuardrailContextualGroundingFilter",
                )
            })?,
            detected: self.detected,
        })
    }
}
