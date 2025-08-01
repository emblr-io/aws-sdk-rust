// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAppReplicationConfigurationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutAppReplicationConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutAppReplicationConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutAppReplicationConfigurationOutput`](crate::operation::put_app_replication_configuration::PutAppReplicationConfigurationOutput).
    pub fn builder() -> crate::operation::put_app_replication_configuration::builders::PutAppReplicationConfigurationOutputBuilder {
        crate::operation::put_app_replication_configuration::builders::PutAppReplicationConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutAppReplicationConfigurationOutput`](crate::operation::put_app_replication_configuration::PutAppReplicationConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAppReplicationConfigurationOutputBuilder {
    _request_id: Option<String>,
}
impl PutAppReplicationConfigurationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutAppReplicationConfigurationOutput`](crate::operation::put_app_replication_configuration::PutAppReplicationConfigurationOutput).
    pub fn build(self) -> crate::operation::put_app_replication_configuration::PutAppReplicationConfigurationOutput {
        crate::operation::put_app_replication_configuration::PutAppReplicationConfigurationOutput {
            _request_id: self._request_id,
        }
    }
}
