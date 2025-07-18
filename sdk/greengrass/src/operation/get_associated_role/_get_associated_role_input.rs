// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAssociatedRoleInput {
    /// The ID of the Greengrass group.
    pub group_id: ::std::option::Option<::std::string::String>,
}
impl GetAssociatedRoleInput {
    /// The ID of the Greengrass group.
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
}
impl GetAssociatedRoleInput {
    /// Creates a new builder-style object to manufacture [`GetAssociatedRoleInput`](crate::operation::get_associated_role::GetAssociatedRoleInput).
    pub fn builder() -> crate::operation::get_associated_role::builders::GetAssociatedRoleInputBuilder {
        crate::operation::get_associated_role::builders::GetAssociatedRoleInputBuilder::default()
    }
}

/// A builder for [`GetAssociatedRoleInput`](crate::operation::get_associated_role::GetAssociatedRoleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAssociatedRoleInputBuilder {
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
}
impl GetAssociatedRoleInputBuilder {
    /// The ID of the Greengrass group.
    /// This field is required.
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the Greengrass group.
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// The ID of the Greengrass group.
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// Consumes the builder and constructs a [`GetAssociatedRoleInput`](crate::operation::get_associated_role::GetAssociatedRoleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_associated_role::GetAssociatedRoleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_associated_role::GetAssociatedRoleInput { group_id: self.group_id })
    }
}
