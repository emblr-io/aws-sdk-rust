// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInstanceSnapshotInput {
    /// <p>The name of the snapshot for which you are requesting information.</p>
    pub instance_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetInstanceSnapshotInput {
    /// <p>The name of the snapshot for which you are requesting information.</p>
    pub fn instance_snapshot_name(&self) -> ::std::option::Option<&str> {
        self.instance_snapshot_name.as_deref()
    }
}
impl GetInstanceSnapshotInput {
    /// Creates a new builder-style object to manufacture [`GetInstanceSnapshotInput`](crate::operation::get_instance_snapshot::GetInstanceSnapshotInput).
    pub fn builder() -> crate::operation::get_instance_snapshot::builders::GetInstanceSnapshotInputBuilder {
        crate::operation::get_instance_snapshot::builders::GetInstanceSnapshotInputBuilder::default()
    }
}

/// A builder for [`GetInstanceSnapshotInput`](crate::operation::get_instance_snapshot::GetInstanceSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInstanceSnapshotInputBuilder {
    pub(crate) instance_snapshot_name: ::std::option::Option<::std::string::String>,
}
impl GetInstanceSnapshotInputBuilder {
    /// <p>The name of the snapshot for which you are requesting information.</p>
    /// This field is required.
    pub fn instance_snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the snapshot for which you are requesting information.</p>
    pub fn set_instance_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_snapshot_name = input;
        self
    }
    /// <p>The name of the snapshot for which you are requesting information.</p>
    pub fn get_instance_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_snapshot_name
    }
    /// Consumes the builder and constructs a [`GetInstanceSnapshotInput`](crate::operation::get_instance_snapshot::GetInstanceSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_instance_snapshot::GetInstanceSnapshotInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_instance_snapshot::GetInstanceSnapshotInput {
            instance_snapshot_name: self.instance_snapshot_name,
        })
    }
}
