// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMountTargetInput {
    /// <p>The ID of the mount target to delete (String).</p>
    pub mount_target_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMountTargetInput {
    /// <p>The ID of the mount target to delete (String).</p>
    pub fn mount_target_id(&self) -> ::std::option::Option<&str> {
        self.mount_target_id.as_deref()
    }
}
impl DeleteMountTargetInput {
    /// Creates a new builder-style object to manufacture [`DeleteMountTargetInput`](crate::operation::delete_mount_target::DeleteMountTargetInput).
    pub fn builder() -> crate::operation::delete_mount_target::builders::DeleteMountTargetInputBuilder {
        crate::operation::delete_mount_target::builders::DeleteMountTargetInputBuilder::default()
    }
}

/// A builder for [`DeleteMountTargetInput`](crate::operation::delete_mount_target::DeleteMountTargetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMountTargetInputBuilder {
    pub(crate) mount_target_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMountTargetInputBuilder {
    /// <p>The ID of the mount target to delete (String).</p>
    /// This field is required.
    pub fn mount_target_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mount_target_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the mount target to delete (String).</p>
    pub fn set_mount_target_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mount_target_id = input;
        self
    }
    /// <p>The ID of the mount target to delete (String).</p>
    pub fn get_mount_target_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.mount_target_id
    }
    /// Consumes the builder and constructs a [`DeleteMountTargetInput`](crate::operation::delete_mount_target::DeleteMountTargetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_mount_target::DeleteMountTargetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_mount_target::DeleteMountTargetInput {
            mount_target_id: self.mount_target_id,
        })
    }
}
