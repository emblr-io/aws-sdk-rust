// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to get information about a specified reusable delegation set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetReusableDelegationSetInput {
    /// <p>The ID of the reusable delegation set that you want to get a list of name servers for.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetReusableDelegationSetInput {
    /// <p>The ID of the reusable delegation set that you want to get a list of name servers for.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetReusableDelegationSetInput {
    /// Creates a new builder-style object to manufacture [`GetReusableDelegationSetInput`](crate::operation::get_reusable_delegation_set::GetReusableDelegationSetInput).
    pub fn builder() -> crate::operation::get_reusable_delegation_set::builders::GetReusableDelegationSetInputBuilder {
        crate::operation::get_reusable_delegation_set::builders::GetReusableDelegationSetInputBuilder::default()
    }
}

/// A builder for [`GetReusableDelegationSetInput`](crate::operation::get_reusable_delegation_set::GetReusableDelegationSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetReusableDelegationSetInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetReusableDelegationSetInputBuilder {
    /// <p>The ID of the reusable delegation set that you want to get a list of name servers for.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the reusable delegation set that you want to get a list of name servers for.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the reusable delegation set that you want to get a list of name servers for.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetReusableDelegationSetInput`](crate::operation::get_reusable_delegation_set::GetReusableDelegationSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_reusable_delegation_set::GetReusableDelegationSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_reusable_delegation_set::GetReusableDelegationSetInput { id: self.id })
    }
}
