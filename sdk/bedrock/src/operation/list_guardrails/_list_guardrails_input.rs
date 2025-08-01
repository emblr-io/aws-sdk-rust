// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListGuardrailsInput {
    /// <p>The unique identifier of the guardrail. This can be an ID or the ARN.</p>
    pub guardrail_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If there are more results than were returned in the response, the response returns a <code>nextToken</code> that you can send in another <code>ListGuardrails</code> request to see the next batch of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListGuardrailsInput {
    /// <p>The unique identifier of the guardrail. This can be an ID or the ARN.</p>
    pub fn guardrail_identifier(&self) -> ::std::option::Option<&str> {
        self.guardrail_identifier.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If there are more results than were returned in the response, the response returns a <code>nextToken</code> that you can send in another <code>ListGuardrails</code> request to see the next batch of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListGuardrailsInput {
    /// Creates a new builder-style object to manufacture [`ListGuardrailsInput`](crate::operation::list_guardrails::ListGuardrailsInput).
    pub fn builder() -> crate::operation::list_guardrails::builders::ListGuardrailsInputBuilder {
        crate::operation::list_guardrails::builders::ListGuardrailsInputBuilder::default()
    }
}

/// A builder for [`ListGuardrailsInput`](crate::operation::list_guardrails::ListGuardrailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListGuardrailsInputBuilder {
    pub(crate) guardrail_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListGuardrailsInputBuilder {
    /// <p>The unique identifier of the guardrail. This can be an ID or the ARN.</p>
    pub fn guardrail_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.guardrail_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the guardrail. This can be an ID or the ARN.</p>
    pub fn set_guardrail_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.guardrail_identifier = input;
        self
    }
    /// <p>The unique identifier of the guardrail. This can be an ID or the ARN.</p>
    pub fn get_guardrail_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.guardrail_identifier
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If there are more results than were returned in the response, the response returns a <code>nextToken</code> that you can send in another <code>ListGuardrails</code> request to see the next batch of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more results than were returned in the response, the response returns a <code>nextToken</code> that you can send in another <code>ListGuardrails</code> request to see the next batch of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more results than were returned in the response, the response returns a <code>nextToken</code> that you can send in another <code>ListGuardrails</code> request to see the next batch of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListGuardrailsInput`](crate::operation::list_guardrails::ListGuardrailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_guardrails::ListGuardrailsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_guardrails::ListGuardrailsInput {
            guardrail_identifier: self.guardrail_identifier,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
