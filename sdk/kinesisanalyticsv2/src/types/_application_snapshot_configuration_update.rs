// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes updates to whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplicationSnapshotConfigurationUpdate {
    /// <p>Describes updates to whether snapshots are enabled for an application.</p>
    pub snapshots_enabled_update: bool,
}
impl ApplicationSnapshotConfigurationUpdate {
    /// <p>Describes updates to whether snapshots are enabled for an application.</p>
    pub fn snapshots_enabled_update(&self) -> bool {
        self.snapshots_enabled_update
    }
}
impl ApplicationSnapshotConfigurationUpdate {
    /// Creates a new builder-style object to manufacture [`ApplicationSnapshotConfigurationUpdate`](crate::types::ApplicationSnapshotConfigurationUpdate).
    pub fn builder() -> crate::types::builders::ApplicationSnapshotConfigurationUpdateBuilder {
        crate::types::builders::ApplicationSnapshotConfigurationUpdateBuilder::default()
    }
}

/// A builder for [`ApplicationSnapshotConfigurationUpdate`](crate::types::ApplicationSnapshotConfigurationUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationSnapshotConfigurationUpdateBuilder {
    pub(crate) snapshots_enabled_update: ::std::option::Option<bool>,
}
impl ApplicationSnapshotConfigurationUpdateBuilder {
    /// <p>Describes updates to whether snapshots are enabled for an application.</p>
    /// This field is required.
    pub fn snapshots_enabled_update(mut self, input: bool) -> Self {
        self.snapshots_enabled_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes updates to whether snapshots are enabled for an application.</p>
    pub fn set_snapshots_enabled_update(mut self, input: ::std::option::Option<bool>) -> Self {
        self.snapshots_enabled_update = input;
        self
    }
    /// <p>Describes updates to whether snapshots are enabled for an application.</p>
    pub fn get_snapshots_enabled_update(&self) -> &::std::option::Option<bool> {
        &self.snapshots_enabled_update
    }
    /// Consumes the builder and constructs a [`ApplicationSnapshotConfigurationUpdate`](crate::types::ApplicationSnapshotConfigurationUpdate).
    /// This method will fail if any of the following fields are not set:
    /// - [`snapshots_enabled_update`](crate::types::builders::ApplicationSnapshotConfigurationUpdateBuilder::snapshots_enabled_update)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ApplicationSnapshotConfigurationUpdate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ApplicationSnapshotConfigurationUpdate {
            snapshots_enabled_update: self.snapshots_enabled_update.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "snapshots_enabled_update",
                    "snapshots_enabled_update was not specified but it is required when building ApplicationSnapshotConfigurationUpdate",
                )
            })?,
        })
    }
}
