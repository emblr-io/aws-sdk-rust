// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSyncConfigurationOutput {
    /// <p>The details about the sync configuration for which you want to retrieve information.</p>
    pub sync_configuration: ::std::option::Option<crate::types::SyncConfiguration>,
    _request_id: Option<String>,
}
impl GetSyncConfigurationOutput {
    /// <p>The details about the sync configuration for which you want to retrieve information.</p>
    pub fn sync_configuration(&self) -> ::std::option::Option<&crate::types::SyncConfiguration> {
        self.sync_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSyncConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSyncConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetSyncConfigurationOutput`](crate::operation::get_sync_configuration::GetSyncConfigurationOutput).
    pub fn builder() -> crate::operation::get_sync_configuration::builders::GetSyncConfigurationOutputBuilder {
        crate::operation::get_sync_configuration::builders::GetSyncConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetSyncConfigurationOutput`](crate::operation::get_sync_configuration::GetSyncConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSyncConfigurationOutputBuilder {
    pub(crate) sync_configuration: ::std::option::Option<crate::types::SyncConfiguration>,
    _request_id: Option<String>,
}
impl GetSyncConfigurationOutputBuilder {
    /// <p>The details about the sync configuration for which you want to retrieve information.</p>
    /// This field is required.
    pub fn sync_configuration(mut self, input: crate::types::SyncConfiguration) -> Self {
        self.sync_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details about the sync configuration for which you want to retrieve information.</p>
    pub fn set_sync_configuration(mut self, input: ::std::option::Option<crate::types::SyncConfiguration>) -> Self {
        self.sync_configuration = input;
        self
    }
    /// <p>The details about the sync configuration for which you want to retrieve information.</p>
    pub fn get_sync_configuration(&self) -> &::std::option::Option<crate::types::SyncConfiguration> {
        &self.sync_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSyncConfigurationOutput`](crate::operation::get_sync_configuration::GetSyncConfigurationOutput).
    pub fn build(self) -> crate::operation::get_sync_configuration::GetSyncConfigurationOutput {
        crate::operation::get_sync_configuration::GetSyncConfigurationOutput {
            sync_configuration: self.sync_configuration,
            _request_id: self._request_id,
        }
    }
}
