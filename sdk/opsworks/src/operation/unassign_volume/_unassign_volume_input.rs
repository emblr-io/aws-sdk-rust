// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnassignVolumeInput {
    /// <p>The volume ID.</p>
    pub volume_id: ::std::option::Option<::std::string::String>,
}
impl UnassignVolumeInput {
    /// <p>The volume ID.</p>
    pub fn volume_id(&self) -> ::std::option::Option<&str> {
        self.volume_id.as_deref()
    }
}
impl UnassignVolumeInput {
    /// Creates a new builder-style object to manufacture [`UnassignVolumeInput`](crate::operation::unassign_volume::UnassignVolumeInput).
    pub fn builder() -> crate::operation::unassign_volume::builders::UnassignVolumeInputBuilder {
        crate::operation::unassign_volume::builders::UnassignVolumeInputBuilder::default()
    }
}

/// A builder for [`UnassignVolumeInput`](crate::operation::unassign_volume::UnassignVolumeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnassignVolumeInputBuilder {
    pub(crate) volume_id: ::std::option::Option<::std::string::String>,
}
impl UnassignVolumeInputBuilder {
    /// <p>The volume ID.</p>
    /// This field is required.
    pub fn volume_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume ID.</p>
    pub fn set_volume_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_id = input;
        self
    }
    /// <p>The volume ID.</p>
    pub fn get_volume_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_id
    }
    /// Consumes the builder and constructs a [`UnassignVolumeInput`](crate::operation::unassign_volume::UnassignVolumeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::unassign_volume::UnassignVolumeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::unassign_volume::UnassignVolumeInput { volume_id: self.volume_id })
    }
}
