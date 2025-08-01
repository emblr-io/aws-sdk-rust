// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Shows the results of the human in the loop evaluation. If there is no HumanLoopArn, the input did not trigger human review.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HumanLoopActivationOutput {
    /// <p>The Amazon Resource Name (ARN) of the HumanLoop created.</p>
    pub human_loop_arn: ::std::option::Option<::std::string::String>,
    /// <p>Shows if and why human review was needed.</p>
    pub human_loop_activation_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Shows the result of condition evaluations, including those conditions which activated a human review.</p>
    pub human_loop_activation_conditions_evaluation_results: ::std::option::Option<::std::string::String>,
}
impl HumanLoopActivationOutput {
    /// <p>The Amazon Resource Name (ARN) of the HumanLoop created.</p>
    pub fn human_loop_arn(&self) -> ::std::option::Option<&str> {
        self.human_loop_arn.as_deref()
    }
    /// <p>Shows if and why human review was needed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.human_loop_activation_reasons.is_none()`.
    pub fn human_loop_activation_reasons(&self) -> &[::std::string::String] {
        self.human_loop_activation_reasons.as_deref().unwrap_or_default()
    }
    /// <p>Shows the result of condition evaluations, including those conditions which activated a human review.</p>
    pub fn human_loop_activation_conditions_evaluation_results(&self) -> ::std::option::Option<&str> {
        self.human_loop_activation_conditions_evaluation_results.as_deref()
    }
}
impl HumanLoopActivationOutput {
    /// Creates a new builder-style object to manufacture [`HumanLoopActivationOutput`](crate::types::HumanLoopActivationOutput).
    pub fn builder() -> crate::types::builders::HumanLoopActivationOutputBuilder {
        crate::types::builders::HumanLoopActivationOutputBuilder::default()
    }
}

/// A builder for [`HumanLoopActivationOutput`](crate::types::HumanLoopActivationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HumanLoopActivationOutputBuilder {
    pub(crate) human_loop_arn: ::std::option::Option<::std::string::String>,
    pub(crate) human_loop_activation_reasons: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) human_loop_activation_conditions_evaluation_results: ::std::option::Option<::std::string::String>,
}
impl HumanLoopActivationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the HumanLoop created.</p>
    pub fn human_loop_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.human_loop_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the HumanLoop created.</p>
    pub fn set_human_loop_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.human_loop_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the HumanLoop created.</p>
    pub fn get_human_loop_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.human_loop_arn
    }
    /// Appends an item to `human_loop_activation_reasons`.
    ///
    /// To override the contents of this collection use [`set_human_loop_activation_reasons`](Self::set_human_loop_activation_reasons).
    ///
    /// <p>Shows if and why human review was needed.</p>
    pub fn human_loop_activation_reasons(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.human_loop_activation_reasons.unwrap_or_default();
        v.push(input.into());
        self.human_loop_activation_reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>Shows if and why human review was needed.</p>
    pub fn set_human_loop_activation_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.human_loop_activation_reasons = input;
        self
    }
    /// <p>Shows if and why human review was needed.</p>
    pub fn get_human_loop_activation_reasons(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.human_loop_activation_reasons
    }
    /// <p>Shows the result of condition evaluations, including those conditions which activated a human review.</p>
    pub fn human_loop_activation_conditions_evaluation_results(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.human_loop_activation_conditions_evaluation_results = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Shows the result of condition evaluations, including those conditions which activated a human review.</p>
    pub fn set_human_loop_activation_conditions_evaluation_results(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.human_loop_activation_conditions_evaluation_results = input;
        self
    }
    /// <p>Shows the result of condition evaluations, including those conditions which activated a human review.</p>
    pub fn get_human_loop_activation_conditions_evaluation_results(&self) -> &::std::option::Option<::std::string::String> {
        &self.human_loop_activation_conditions_evaluation_results
    }
    /// Consumes the builder and constructs a [`HumanLoopActivationOutput`](crate::types::HumanLoopActivationOutput).
    pub fn build(self) -> crate::types::HumanLoopActivationOutput {
        crate::types::HumanLoopActivationOutput {
            human_loop_arn: self.human_loop_arn,
            human_loop_activation_reasons: self.human_loop_activation_reasons,
            human_loop_activation_conditions_evaluation_results: self.human_loop_activation_conditions_evaluation_results,
        }
    }
}
