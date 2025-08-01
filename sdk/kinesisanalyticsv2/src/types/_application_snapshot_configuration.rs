// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplicationSnapshotConfiguration {
    /// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
    pub snapshots_enabled: bool,
}
impl ApplicationSnapshotConfiguration {
    /// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
    pub fn snapshots_enabled(&self) -> bool {
        self.snapshots_enabled
    }
}
impl ApplicationSnapshotConfiguration {
    /// Creates a new builder-style object to manufacture [`ApplicationSnapshotConfiguration`](crate::types::ApplicationSnapshotConfiguration).
    pub fn builder() -> crate::types::builders::ApplicationSnapshotConfigurationBuilder {
        crate::types::builders::ApplicationSnapshotConfigurationBuilder::default()
    }
}

/// A builder for [`ApplicationSnapshotConfiguration`](crate::types::ApplicationSnapshotConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationSnapshotConfigurationBuilder {
    pub(crate) snapshots_enabled: ::std::option::Option<bool>,
}
impl ApplicationSnapshotConfigurationBuilder {
    /// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
    /// This field is required.
    pub fn snapshots_enabled(mut self, input: bool) -> Self {
        self.snapshots_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
    pub fn set_snapshots_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.snapshots_enabled = input;
        self
    }
    /// <p>Describes whether snapshots are enabled for a Managed Service for Apache Flink application.</p>
    pub fn get_snapshots_enabled(&self) -> &::std::option::Option<bool> {
        &self.snapshots_enabled
    }
    /// Consumes the builder and constructs a [`ApplicationSnapshotConfiguration`](crate::types::ApplicationSnapshotConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`snapshots_enabled`](crate::types::builders::ApplicationSnapshotConfigurationBuilder::snapshots_enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::ApplicationSnapshotConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ApplicationSnapshotConfiguration {
            snapshots_enabled: self.snapshots_enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "snapshots_enabled",
                    "snapshots_enabled was not specified but it is required when building ApplicationSnapshotConfiguration",
                )
            })?,
        })
    }
}
