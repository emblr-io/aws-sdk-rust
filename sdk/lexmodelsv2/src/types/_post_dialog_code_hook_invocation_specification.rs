// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies next steps to run after the dialog code hook finishes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PostDialogCodeHookInvocationSpecification {
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub success_response: ::std::option::Option<crate::types::ResponseSpecification>,
    /// <p>Specifics the next step the bot runs after the dialog code hook finishes successfully.</p>
    pub success_next_step: ::std::option::Option<crate::types::DialogState>,
    /// <p>A list of conditional branches to evaluate after the dialog code hook finishes successfully.</p>
    pub success_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub failure_response: ::std::option::Option<crate::types::ResponseSpecification>,
    /// <p>Specifies the next step the bot runs after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub failure_next_step: ::std::option::Option<crate::types::DialogState>,
    /// <p>A list of conditional branches to evaluate after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub failure_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub timeout_response: ::std::option::Option<crate::types::ResponseSpecification>,
    /// <p>Specifies the next step that the bot runs when the code hook times out.</p>
    pub timeout_next_step: ::std::option::Option<crate::types::DialogState>,
    /// <p>A list of conditional branches to evaluate if the code hook times out.</p>
    pub timeout_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
}
impl PostDialogCodeHookInvocationSpecification {
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn success_response(&self) -> ::std::option::Option<&crate::types::ResponseSpecification> {
        self.success_response.as_ref()
    }
    /// <p>Specifics the next step the bot runs after the dialog code hook finishes successfully.</p>
    pub fn success_next_step(&self) -> ::std::option::Option<&crate::types::DialogState> {
        self.success_next_step.as_ref()
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook finishes successfully.</p>
    pub fn success_conditional(&self) -> ::std::option::Option<&crate::types::ConditionalSpecification> {
        self.success_conditional.as_ref()
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn failure_response(&self) -> ::std::option::Option<&crate::types::ResponseSpecification> {
        self.failure_response.as_ref()
    }
    /// <p>Specifies the next step the bot runs after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn failure_next_step(&self) -> ::std::option::Option<&crate::types::DialogState> {
        self.failure_next_step.as_ref()
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn failure_conditional(&self) -> ::std::option::Option<&crate::types::ConditionalSpecification> {
        self.failure_conditional.as_ref()
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn timeout_response(&self) -> ::std::option::Option<&crate::types::ResponseSpecification> {
        self.timeout_response.as_ref()
    }
    /// <p>Specifies the next step that the bot runs when the code hook times out.</p>
    pub fn timeout_next_step(&self) -> ::std::option::Option<&crate::types::DialogState> {
        self.timeout_next_step.as_ref()
    }
    /// <p>A list of conditional branches to evaluate if the code hook times out.</p>
    pub fn timeout_conditional(&self) -> ::std::option::Option<&crate::types::ConditionalSpecification> {
        self.timeout_conditional.as_ref()
    }
}
impl PostDialogCodeHookInvocationSpecification {
    /// Creates a new builder-style object to manufacture [`PostDialogCodeHookInvocationSpecification`](crate::types::PostDialogCodeHookInvocationSpecification).
    pub fn builder() -> crate::types::builders::PostDialogCodeHookInvocationSpecificationBuilder {
        crate::types::builders::PostDialogCodeHookInvocationSpecificationBuilder::default()
    }
}

/// A builder for [`PostDialogCodeHookInvocationSpecification`](crate::types::PostDialogCodeHookInvocationSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PostDialogCodeHookInvocationSpecificationBuilder {
    pub(crate) success_response: ::std::option::Option<crate::types::ResponseSpecification>,
    pub(crate) success_next_step: ::std::option::Option<crate::types::DialogState>,
    pub(crate) success_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
    pub(crate) failure_response: ::std::option::Option<crate::types::ResponseSpecification>,
    pub(crate) failure_next_step: ::std::option::Option<crate::types::DialogState>,
    pub(crate) failure_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
    pub(crate) timeout_response: ::std::option::Option<crate::types::ResponseSpecification>,
    pub(crate) timeout_next_step: ::std::option::Option<crate::types::DialogState>,
    pub(crate) timeout_conditional: ::std::option::Option<crate::types::ConditionalSpecification>,
}
impl PostDialogCodeHookInvocationSpecificationBuilder {
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn success_response(mut self, input: crate::types::ResponseSpecification) -> Self {
        self.success_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn set_success_response(mut self, input: ::std::option::Option<crate::types::ResponseSpecification>) -> Self {
        self.success_response = input;
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn get_success_response(&self) -> &::std::option::Option<crate::types::ResponseSpecification> {
        &self.success_response
    }
    /// <p>Specifics the next step the bot runs after the dialog code hook finishes successfully.</p>
    pub fn success_next_step(mut self, input: crate::types::DialogState) -> Self {
        self.success_next_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifics the next step the bot runs after the dialog code hook finishes successfully.</p>
    pub fn set_success_next_step(mut self, input: ::std::option::Option<crate::types::DialogState>) -> Self {
        self.success_next_step = input;
        self
    }
    /// <p>Specifics the next step the bot runs after the dialog code hook finishes successfully.</p>
    pub fn get_success_next_step(&self) -> &::std::option::Option<crate::types::DialogState> {
        &self.success_next_step
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook finishes successfully.</p>
    pub fn success_conditional(mut self, input: crate::types::ConditionalSpecification) -> Self {
        self.success_conditional = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook finishes successfully.</p>
    pub fn set_success_conditional(mut self, input: ::std::option::Option<crate::types::ConditionalSpecification>) -> Self {
        self.success_conditional = input;
        self
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook finishes successfully.</p>
    pub fn get_success_conditional(&self) -> &::std::option::Option<crate::types::ConditionalSpecification> {
        &self.success_conditional
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn failure_response(mut self, input: crate::types::ResponseSpecification) -> Self {
        self.failure_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn set_failure_response(mut self, input: ::std::option::Option<crate::types::ResponseSpecification>) -> Self {
        self.failure_response = input;
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn get_failure_response(&self) -> &::std::option::Option<crate::types::ResponseSpecification> {
        &self.failure_response
    }
    /// <p>Specifies the next step the bot runs after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn failure_next_step(mut self, input: crate::types::DialogState) -> Self {
        self.failure_next_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the next step the bot runs after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn set_failure_next_step(mut self, input: ::std::option::Option<crate::types::DialogState>) -> Self {
        self.failure_next_step = input;
        self
    }
    /// <p>Specifies the next step the bot runs after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn get_failure_next_step(&self) -> &::std::option::Option<crate::types::DialogState> {
        &self.failure_next_step
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn failure_conditional(mut self, input: crate::types::ConditionalSpecification) -> Self {
        self.failure_conditional = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn set_failure_conditional(mut self, input: ::std::option::Option<crate::types::ConditionalSpecification>) -> Self {
        self.failure_conditional = input;
        self
    }
    /// <p>A list of conditional branches to evaluate after the dialog code hook throws an exception or returns with the <code>State</code> field of the <code>Intent</code> object set to <code>Failed</code>.</p>
    pub fn get_failure_conditional(&self) -> &::std::option::Option<crate::types::ConditionalSpecification> {
        &self.failure_conditional
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn timeout_response(mut self, input: crate::types::ResponseSpecification) -> Self {
        self.timeout_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn set_timeout_response(mut self, input: ::std::option::Option<crate::types::ResponseSpecification>) -> Self {
        self.timeout_response = input;
        self
    }
    /// <p>Specifies a list of message groups that Amazon Lex uses to respond the user input.</p>
    pub fn get_timeout_response(&self) -> &::std::option::Option<crate::types::ResponseSpecification> {
        &self.timeout_response
    }
    /// <p>Specifies the next step that the bot runs when the code hook times out.</p>
    pub fn timeout_next_step(mut self, input: crate::types::DialogState) -> Self {
        self.timeout_next_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the next step that the bot runs when the code hook times out.</p>
    pub fn set_timeout_next_step(mut self, input: ::std::option::Option<crate::types::DialogState>) -> Self {
        self.timeout_next_step = input;
        self
    }
    /// <p>Specifies the next step that the bot runs when the code hook times out.</p>
    pub fn get_timeout_next_step(&self) -> &::std::option::Option<crate::types::DialogState> {
        &self.timeout_next_step
    }
    /// <p>A list of conditional branches to evaluate if the code hook times out.</p>
    pub fn timeout_conditional(mut self, input: crate::types::ConditionalSpecification) -> Self {
        self.timeout_conditional = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of conditional branches to evaluate if the code hook times out.</p>
    pub fn set_timeout_conditional(mut self, input: ::std::option::Option<crate::types::ConditionalSpecification>) -> Self {
        self.timeout_conditional = input;
        self
    }
    /// <p>A list of conditional branches to evaluate if the code hook times out.</p>
    pub fn get_timeout_conditional(&self) -> &::std::option::Option<crate::types::ConditionalSpecification> {
        &self.timeout_conditional
    }
    /// Consumes the builder and constructs a [`PostDialogCodeHookInvocationSpecification`](crate::types::PostDialogCodeHookInvocationSpecification).
    pub fn build(self) -> crate::types::PostDialogCodeHookInvocationSpecification {
        crate::types::PostDialogCodeHookInvocationSpecification {
            success_response: self.success_response,
            success_next_step: self.success_next_step,
            success_conditional: self.success_conditional,
            failure_response: self.failure_response,
            failure_next_step: self.failure_next_step,
            failure_conditional: self.failure_conditional,
            timeout_response: self.timeout_response,
            timeout_next_step: self.timeout_next_step,
            timeout_conditional: self.timeout_conditional,
        }
    }
}
