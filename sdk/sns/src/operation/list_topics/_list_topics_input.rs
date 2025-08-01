// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTopicsInput {
    /// <p>Token returned by the previous <code>ListTopics</code> request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListTopicsInput {
    /// <p>Token returned by the previous <code>ListTopics</code> request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListTopicsInput {
    /// Creates a new builder-style object to manufacture [`ListTopicsInput`](crate::operation::list_topics::ListTopicsInput).
    pub fn builder() -> crate::operation::list_topics::builders::ListTopicsInputBuilder {
        crate::operation::list_topics::builders::ListTopicsInputBuilder::default()
    }
}

/// A builder for [`ListTopicsInput`](crate::operation::list_topics::ListTopicsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTopicsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListTopicsInputBuilder {
    /// <p>Token returned by the previous <code>ListTopics</code> request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Token returned by the previous <code>ListTopics</code> request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Token returned by the previous <code>ListTopics</code> request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListTopicsInput`](crate::operation::list_topics::ListTopicsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_topics::ListTopicsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_topics::ListTopicsInput { next_token: self.next_token })
    }
}
