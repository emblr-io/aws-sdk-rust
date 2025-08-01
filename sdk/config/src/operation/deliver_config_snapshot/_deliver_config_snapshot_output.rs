// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for the <code>DeliverConfigSnapshot</code> action, in JSON format.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeliverConfigSnapshotOutput {
    /// <p>The ID of the snapshot that is being created.</p>
    pub config_snapshot_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeliverConfigSnapshotOutput {
    /// <p>The ID of the snapshot that is being created.</p>
    pub fn config_snapshot_id(&self) -> ::std::option::Option<&str> {
        self.config_snapshot_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeliverConfigSnapshotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeliverConfigSnapshotOutput {
    /// Creates a new builder-style object to manufacture [`DeliverConfigSnapshotOutput`](crate::operation::deliver_config_snapshot::DeliverConfigSnapshotOutput).
    pub fn builder() -> crate::operation::deliver_config_snapshot::builders::DeliverConfigSnapshotOutputBuilder {
        crate::operation::deliver_config_snapshot::builders::DeliverConfigSnapshotOutputBuilder::default()
    }
}

/// A builder for [`DeliverConfigSnapshotOutput`](crate::operation::deliver_config_snapshot::DeliverConfigSnapshotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeliverConfigSnapshotOutputBuilder {
    pub(crate) config_snapshot_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeliverConfigSnapshotOutputBuilder {
    /// <p>The ID of the snapshot that is being created.</p>
    pub fn config_snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the snapshot that is being created.</p>
    pub fn set_config_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_snapshot_id = input;
        self
    }
    /// <p>The ID of the snapshot that is being created.</p>
    pub fn get_config_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_snapshot_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeliverConfigSnapshotOutput`](crate::operation::deliver_config_snapshot::DeliverConfigSnapshotOutput).
    pub fn build(self) -> crate::operation::deliver_config_snapshot::DeliverConfigSnapshotOutput {
        crate::operation::deliver_config_snapshot::DeliverConfigSnapshotOutput {
            config_snapshot_id: self.config_snapshot_id,
            _request_id: self._request_id,
        }
    }
}
