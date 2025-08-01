// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the prompts that Amazon Lex uses while a bot is waiting for customer input.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WaitAndContinueSpecification {
    /// <p>The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.</p>
    pub waiting_response: ::std::option::Option<crate::types::ResponseSpecification>,
    /// <p>The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.</p>
    pub continue_response: ::std::option::Option<crate::types::ResponseSpecification>,
    /// <p>A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.</p>
    pub still_waiting_response: ::std::option::Option<crate::types::StillWaitingResponseSpecification>,
    /// <p>Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used. If the <code>active</code> field isn't specified, the default is true.</p>
    pub active: ::std::option::Option<bool>,
}
impl WaitAndContinueSpecification {
    /// <p>The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.</p>
    pub fn waiting_response(&self) -> ::std::option::Option<&crate::types::ResponseSpecification> {
        self.waiting_response.as_ref()
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.</p>
    pub fn continue_response(&self) -> ::std::option::Option<&crate::types::ResponseSpecification> {
        self.continue_response.as_ref()
    }
    /// <p>A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.</p>
    pub fn still_waiting_response(&self) -> ::std::option::Option<&crate::types::StillWaitingResponseSpecification> {
        self.still_waiting_response.as_ref()
    }
    /// <p>Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used. If the <code>active</code> field isn't specified, the default is true.</p>
    pub fn active(&self) -> ::std::option::Option<bool> {
        self.active
    }
}
impl WaitAndContinueSpecification {
    /// Creates a new builder-style object to manufacture [`WaitAndContinueSpecification`](crate::types::WaitAndContinueSpecification).
    pub fn builder() -> crate::types::builders::WaitAndContinueSpecificationBuilder {
        crate::types::builders::WaitAndContinueSpecificationBuilder::default()
    }
}

/// A builder for [`WaitAndContinueSpecification`](crate::types::WaitAndContinueSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WaitAndContinueSpecificationBuilder {
    pub(crate) waiting_response: ::std::option::Option<crate::types::ResponseSpecification>,
    pub(crate) continue_response: ::std::option::Option<crate::types::ResponseSpecification>,
    pub(crate) still_waiting_response: ::std::option::Option<crate::types::StillWaitingResponseSpecification>,
    pub(crate) active: ::std::option::Option<bool>,
}
impl WaitAndContinueSpecificationBuilder {
    /// <p>The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.</p>
    /// This field is required.
    pub fn waiting_response(mut self, input: crate::types::ResponseSpecification) -> Self {
        self.waiting_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.</p>
    pub fn set_waiting_response(mut self, input: ::std::option::Option<crate::types::ResponseSpecification>) -> Self {
        self.waiting_response = input;
        self
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is waiting for the conversation to continue.</p>
    pub fn get_waiting_response(&self) -> &::std::option::Option<crate::types::ResponseSpecification> {
        &self.waiting_response
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.</p>
    /// This field is required.
    pub fn continue_response(mut self, input: crate::types::ResponseSpecification) -> Self {
        self.continue_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.</p>
    pub fn set_continue_response(mut self, input: ::std::option::Option<crate::types::ResponseSpecification>) -> Self {
        self.continue_response = input;
        self
    }
    /// <p>The response that Amazon Lex sends to indicate that the bot is ready to continue the conversation.</p>
    pub fn get_continue_response(&self) -> &::std::option::Option<crate::types::ResponseSpecification> {
        &self.continue_response
    }
    /// <p>A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.</p>
    pub fn still_waiting_response(mut self, input: crate::types::StillWaitingResponseSpecification) -> Self {
        self.still_waiting_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.</p>
    pub fn set_still_waiting_response(mut self, input: ::std::option::Option<crate::types::StillWaitingResponseSpecification>) -> Self {
        self.still_waiting_response = input;
        self
    }
    /// <p>A response that Amazon Lex sends periodically to the user to indicate that the bot is still waiting for input from the user.</p>
    pub fn get_still_waiting_response(&self) -> &::std::option::Option<crate::types::StillWaitingResponseSpecification> {
        &self.still_waiting_response
    }
    /// <p>Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used. If the <code>active</code> field isn't specified, the default is true.</p>
    pub fn active(mut self, input: bool) -> Self {
        self.active = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used. If the <code>active</code> field isn't specified, the default is true.</p>
    pub fn set_active(mut self, input: ::std::option::Option<bool>) -> Self {
        self.active = input;
        self
    }
    /// <p>Specifies whether the bot will wait for a user to respond. When this field is false, wait and continue responses for a slot aren't used. If the <code>active</code> field isn't specified, the default is true.</p>
    pub fn get_active(&self) -> &::std::option::Option<bool> {
        &self.active
    }
    /// Consumes the builder and constructs a [`WaitAndContinueSpecification`](crate::types::WaitAndContinueSpecification).
    pub fn build(self) -> crate::types::WaitAndContinueSpecification {
        crate::types::WaitAndContinueSpecification {
            waiting_response: self.waiting_response,
            continue_response: self.continue_response,
            still_waiting_response: self.still_waiting_response,
            active: self.active,
        }
    }
}
