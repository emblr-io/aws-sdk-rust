// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSnapshotCopyConfigurationOutput {
    /// <p>The deleted snapshot copy configuration object.</p>
    pub snapshot_copy_configuration: ::std::option::Option<crate::types::SnapshotCopyConfiguration>,
    _request_id: Option<String>,
}
impl DeleteSnapshotCopyConfigurationOutput {
    /// <p>The deleted snapshot copy configuration object.</p>
    pub fn snapshot_copy_configuration(&self) -> ::std::option::Option<&crate::types::SnapshotCopyConfiguration> {
        self.snapshot_copy_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteSnapshotCopyConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteSnapshotCopyConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteSnapshotCopyConfigurationOutput`](crate::operation::delete_snapshot_copy_configuration::DeleteSnapshotCopyConfigurationOutput).
    pub fn builder() -> crate::operation::delete_snapshot_copy_configuration::builders::DeleteSnapshotCopyConfigurationOutputBuilder {
        crate::operation::delete_snapshot_copy_configuration::builders::DeleteSnapshotCopyConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteSnapshotCopyConfigurationOutput`](crate::operation::delete_snapshot_copy_configuration::DeleteSnapshotCopyConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSnapshotCopyConfigurationOutputBuilder {
    pub(crate) snapshot_copy_configuration: ::std::option::Option<crate::types::SnapshotCopyConfiguration>,
    _request_id: Option<String>,
}
impl DeleteSnapshotCopyConfigurationOutputBuilder {
    /// <p>The deleted snapshot copy configuration object.</p>
    /// This field is required.
    pub fn snapshot_copy_configuration(mut self, input: crate::types::SnapshotCopyConfiguration) -> Self {
        self.snapshot_copy_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deleted snapshot copy configuration object.</p>
    pub fn set_snapshot_copy_configuration(mut self, input: ::std::option::Option<crate::types::SnapshotCopyConfiguration>) -> Self {
        self.snapshot_copy_configuration = input;
        self
    }
    /// <p>The deleted snapshot copy configuration object.</p>
    pub fn get_snapshot_copy_configuration(&self) -> &::std::option::Option<crate::types::SnapshotCopyConfiguration> {
        &self.snapshot_copy_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteSnapshotCopyConfigurationOutput`](crate::operation::delete_snapshot_copy_configuration::DeleteSnapshotCopyConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_snapshot_copy_configuration::DeleteSnapshotCopyConfigurationOutput {
        crate::operation::delete_snapshot_copy_configuration::DeleteSnapshotCopyConfigurationOutput {
            snapshot_copy_configuration: self.snapshot_copy_configuration,
            _request_id: self._request_id,
        }
    }
}
