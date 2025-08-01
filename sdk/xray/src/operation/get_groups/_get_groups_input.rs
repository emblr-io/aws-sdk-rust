// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGroupsInput {
    /// <p>Pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetGroupsInput {
    /// <p>Pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetGroupsInput {
    /// Creates a new builder-style object to manufacture [`GetGroupsInput`](crate::operation::get_groups::GetGroupsInput).
    pub fn builder() -> crate::operation::get_groups::builders::GetGroupsInputBuilder {
        crate::operation::get_groups::builders::GetGroupsInputBuilder::default()
    }
}

/// A builder for [`GetGroupsInput`](crate::operation::get_groups::GetGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGroupsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetGroupsInputBuilder {
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
    /// Consumes the builder and constructs a [`GetGroupsInput`](crate::operation::get_groups::GetGroupsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_groups::GetGroupsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_groups::GetGroupsInput { next_token: self.next_token })
    }
}
