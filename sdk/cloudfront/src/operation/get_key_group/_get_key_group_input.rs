// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetKeyGroupInput {
    /// <p>The identifier of the key group that you are getting. To get the identifier, use <code>ListKeyGroups</code>.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetKeyGroupInput {
    /// <p>The identifier of the key group that you are getting. To get the identifier, use <code>ListKeyGroups</code>.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetKeyGroupInput {
    /// Creates a new builder-style object to manufacture [`GetKeyGroupInput`](crate::operation::get_key_group::GetKeyGroupInput).
    pub fn builder() -> crate::operation::get_key_group::builders::GetKeyGroupInputBuilder {
        crate::operation::get_key_group::builders::GetKeyGroupInputBuilder::default()
    }
}

/// A builder for [`GetKeyGroupInput`](crate::operation::get_key_group::GetKeyGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetKeyGroupInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetKeyGroupInputBuilder {
    /// <p>The identifier of the key group that you are getting. To get the identifier, use <code>ListKeyGroups</code>.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the key group that you are getting. To get the identifier, use <code>ListKeyGroups</code>.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the key group that you are getting. To get the identifier, use <code>ListKeyGroups</code>.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetKeyGroupInput`](crate::operation::get_key_group::GetKeyGroupInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_key_group::GetKeyGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_key_group::GetKeyGroupInput { id: self.id })
    }
}
