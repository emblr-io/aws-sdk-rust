// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSamplingRulesInput {
    /// <p>Pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetSamplingRulesInput {
    /// <p>Pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetSamplingRulesInput {
    /// Creates a new builder-style object to manufacture [`GetSamplingRulesInput`](crate::operation::get_sampling_rules::GetSamplingRulesInput).
    pub fn builder() -> crate::operation::get_sampling_rules::builders::GetSamplingRulesInputBuilder {
        crate::operation::get_sampling_rules::builders::GetSamplingRulesInputBuilder::default()
    }
}

/// A builder for [`GetSamplingRulesInput`](crate::operation::get_sampling_rules::GetSamplingRulesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSamplingRulesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetSamplingRulesInputBuilder {
    /// <p>Pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetSamplingRulesInput`](crate::operation::get_sampling_rules::GetSamplingRulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_sampling_rules::GetSamplingRulesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_sampling_rules::GetSamplingRulesInput { next_token: self.next_token })
    }
}
