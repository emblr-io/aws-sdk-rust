// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRuleInput {
    /// <p>The unique ID of the retention rule.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetRuleInput {
    /// <p>The unique ID of the retention rule.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetRuleInput {
    /// Creates a new builder-style object to manufacture [`GetRuleInput`](crate::operation::get_rule::GetRuleInput).
    pub fn builder() -> crate::operation::get_rule::builders::GetRuleInputBuilder {
        crate::operation::get_rule::builders::GetRuleInputBuilder::default()
    }
}

/// A builder for [`GetRuleInput`](crate::operation::get_rule::GetRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRuleInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetRuleInputBuilder {
    /// <p>The unique ID of the retention rule.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the retention rule.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique ID of the retention rule.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetRuleInput`](crate::operation::get_rule::GetRuleInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_rule::GetRuleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_rule::GetRuleInput { identifier: self.identifier })
    }
}
