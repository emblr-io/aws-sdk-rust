// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPermissionGroupInput {
    /// <p>The unique identifier for the permission group.</p>
    pub permission_group_id: ::std::option::Option<::std::string::String>,
}
impl GetPermissionGroupInput {
    /// <p>The unique identifier for the permission group.</p>
    pub fn permission_group_id(&self) -> ::std::option::Option<&str> {
        self.permission_group_id.as_deref()
    }
}
impl GetPermissionGroupInput {
    /// Creates a new builder-style object to manufacture [`GetPermissionGroupInput`](crate::operation::get_permission_group::GetPermissionGroupInput).
    pub fn builder() -> crate::operation::get_permission_group::builders::GetPermissionGroupInputBuilder {
        crate::operation::get_permission_group::builders::GetPermissionGroupInputBuilder::default()
    }
}

/// A builder for [`GetPermissionGroupInput`](crate::operation::get_permission_group::GetPermissionGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPermissionGroupInputBuilder {
    pub(crate) permission_group_id: ::std::option::Option<::std::string::String>,
}
impl GetPermissionGroupInputBuilder {
    /// <p>The unique identifier for the permission group.</p>
    /// This field is required.
    pub fn permission_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the permission group.</p>
    pub fn set_permission_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_group_id = input;
        self
    }
    /// <p>The unique identifier for the permission group.</p>
    pub fn get_permission_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_group_id
    }
    /// Consumes the builder and constructs a [`GetPermissionGroupInput`](crate::operation::get_permission_group::GetPermissionGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_permission_group::GetPermissionGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_permission_group::GetPermissionGroupInput {
            permission_group_id: self.permission_group_id,
        })
    }
}
