// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAutoSnapshotsOutput {
    /// <p>The name of the source instance or disk for the automatic snapshots.</p>
    pub resource_name: ::std::option::Option<::std::string::String>,
    /// <p>The resource type of the automatic snapshot. The possible values are <code>Instance</code>, and <code>Disk</code>.</p>
    pub resource_type: ::std::option::Option<crate::types::ResourceType>,
    /// <p>An array of objects that describe the automatic snapshots that are available for the specified source instance or disk.</p>
    pub auto_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::AutoSnapshotDetails>>,
    _request_id: Option<String>,
}
impl GetAutoSnapshotsOutput {
    /// <p>The name of the source instance or disk for the automatic snapshots.</p>
    pub fn resource_name(&self) -> ::std::option::Option<&str> {
        self.resource_name.as_deref()
    }
    /// <p>The resource type of the automatic snapshot. The possible values are <code>Instance</code>, and <code>Disk</code>.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>An array of objects that describe the automatic snapshots that are available for the specified source instance or disk.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.auto_snapshots.is_none()`.
    pub fn auto_snapshots(&self) -> &[crate::types::AutoSnapshotDetails] {
        self.auto_snapshots.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetAutoSnapshotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAutoSnapshotsOutput {
    /// Creates a new builder-style object to manufacture [`GetAutoSnapshotsOutput`](crate::operation::get_auto_snapshots::GetAutoSnapshotsOutput).
    pub fn builder() -> crate::operation::get_auto_snapshots::builders::GetAutoSnapshotsOutputBuilder {
        crate::operation::get_auto_snapshots::builders::GetAutoSnapshotsOutputBuilder::default()
    }
}

/// A builder for [`GetAutoSnapshotsOutput`](crate::operation::get_auto_snapshots::GetAutoSnapshotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAutoSnapshotsOutputBuilder {
    pub(crate) resource_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) auto_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::AutoSnapshotDetails>>,
    _request_id: Option<String>,
}
impl GetAutoSnapshotsOutputBuilder {
    /// <p>The name of the source instance or disk for the automatic snapshots.</p>
    pub fn resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source instance or disk for the automatic snapshots.</p>
    pub fn set_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_name = input;
        self
    }
    /// <p>The name of the source instance or disk for the automatic snapshots.</p>
    pub fn get_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_name
    }
    /// <p>The resource type of the automatic snapshot. The possible values are <code>Instance</code>, and <code>Disk</code>.</p>
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type of the automatic snapshot. The possible values are <code>Instance</code>, and <code>Disk</code>.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type of the automatic snapshot. The possible values are <code>Instance</code>, and <code>Disk</code>.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// Appends an item to `auto_snapshots`.
    ///
    /// To override the contents of this collection use [`set_auto_snapshots`](Self::set_auto_snapshots).
    ///
    /// <p>An array of objects that describe the automatic snapshots that are available for the specified source instance or disk.</p>
    pub fn auto_snapshots(mut self, input: crate::types::AutoSnapshotDetails) -> Self {
        let mut v = self.auto_snapshots.unwrap_or_default();
        v.push(input);
        self.auto_snapshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the automatic snapshots that are available for the specified source instance or disk.</p>
    pub fn set_auto_snapshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AutoSnapshotDetails>>) -> Self {
        self.auto_snapshots = input;
        self
    }
    /// <p>An array of objects that describe the automatic snapshots that are available for the specified source instance or disk.</p>
    pub fn get_auto_snapshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutoSnapshotDetails>> {
        &self.auto_snapshots
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAutoSnapshotsOutput`](crate::operation::get_auto_snapshots::GetAutoSnapshotsOutput).
    pub fn build(self) -> crate::operation::get_auto_snapshots::GetAutoSnapshotsOutput {
        crate::operation::get_auto_snapshots::GetAutoSnapshotsOutput {
            resource_name: self.resource_name,
            resource_type: self.resource_type,
            auto_snapshots: self.auto_snapshots,
            _request_id: self._request_id,
        }
    }
}
