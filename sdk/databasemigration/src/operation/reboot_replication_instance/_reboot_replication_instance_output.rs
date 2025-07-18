// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RebootReplicationInstanceOutput {
    /// <p>The replication instance that is being rebooted.</p>
    pub replication_instance: ::std::option::Option<crate::types::ReplicationInstance>,
    _request_id: Option<String>,
}
impl RebootReplicationInstanceOutput {
    /// <p>The replication instance that is being rebooted.</p>
    pub fn replication_instance(&self) -> ::std::option::Option<&crate::types::ReplicationInstance> {
        self.replication_instance.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RebootReplicationInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RebootReplicationInstanceOutput {
    /// Creates a new builder-style object to manufacture [`RebootReplicationInstanceOutput`](crate::operation::reboot_replication_instance::RebootReplicationInstanceOutput).
    pub fn builder() -> crate::operation::reboot_replication_instance::builders::RebootReplicationInstanceOutputBuilder {
        crate::operation::reboot_replication_instance::builders::RebootReplicationInstanceOutputBuilder::default()
    }
}

/// A builder for [`RebootReplicationInstanceOutput`](crate::operation::reboot_replication_instance::RebootReplicationInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RebootReplicationInstanceOutputBuilder {
    pub(crate) replication_instance: ::std::option::Option<crate::types::ReplicationInstance>,
    _request_id: Option<String>,
}
impl RebootReplicationInstanceOutputBuilder {
    /// <p>The replication instance that is being rebooted.</p>
    pub fn replication_instance(mut self, input: crate::types::ReplicationInstance) -> Self {
        self.replication_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The replication instance that is being rebooted.</p>
    pub fn set_replication_instance(mut self, input: ::std::option::Option<crate::types::ReplicationInstance>) -> Self {
        self.replication_instance = input;
        self
    }
    /// <p>The replication instance that is being rebooted.</p>
    pub fn get_replication_instance(&self) -> &::std::option::Option<crate::types::ReplicationInstance> {
        &self.replication_instance
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RebootReplicationInstanceOutput`](crate::operation::reboot_replication_instance::RebootReplicationInstanceOutput).
    pub fn build(self) -> crate::operation::reboot_replication_instance::RebootReplicationInstanceOutput {
        crate::operation::reboot_replication_instance::RebootReplicationInstanceOutput {
            replication_instance: self.replication_instance,
            _request_id: self._request_id,
        }
    }
}
