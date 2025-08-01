// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourcePoliciesInput {
    /// <p>Not currently supported.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListResourcePoliciesInput {
    /// <p>Not currently supported.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListResourcePoliciesInput {
    /// Creates a new builder-style object to manufacture [`ListResourcePoliciesInput`](crate::operation::list_resource_policies::ListResourcePoliciesInput).
    pub fn builder() -> crate::operation::list_resource_policies::builders::ListResourcePoliciesInputBuilder {
        crate::operation::list_resource_policies::builders::ListResourcePoliciesInputBuilder::default()
    }
}

/// A builder for [`ListResourcePoliciesInput`](crate::operation::list_resource_policies::ListResourcePoliciesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourcePoliciesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListResourcePoliciesInputBuilder {
    /// <p>Not currently supported.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Not currently supported.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Not currently supported.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListResourcePoliciesInput`](crate::operation::list_resource_policies::ListResourcePoliciesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_resource_policies::ListResourcePoliciesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_resource_policies::ListResourcePoliciesInput { next_token: self.next_token })
    }
}
