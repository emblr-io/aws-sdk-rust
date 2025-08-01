// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetNetworkSettingsOutput {
    /// <p>The network settings.</p>
    pub network_settings: ::std::option::Option<crate::types::NetworkSettings>,
    _request_id: Option<String>,
}
impl GetNetworkSettingsOutput {
    /// <p>The network settings.</p>
    pub fn network_settings(&self) -> ::std::option::Option<&crate::types::NetworkSettings> {
        self.network_settings.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetNetworkSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetNetworkSettingsOutput {
    /// Creates a new builder-style object to manufacture [`GetNetworkSettingsOutput`](crate::operation::get_network_settings::GetNetworkSettingsOutput).
    pub fn builder() -> crate::operation::get_network_settings::builders::GetNetworkSettingsOutputBuilder {
        crate::operation::get_network_settings::builders::GetNetworkSettingsOutputBuilder::default()
    }
}

/// A builder for [`GetNetworkSettingsOutput`](crate::operation::get_network_settings::GetNetworkSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetNetworkSettingsOutputBuilder {
    pub(crate) network_settings: ::std::option::Option<crate::types::NetworkSettings>,
    _request_id: Option<String>,
}
impl GetNetworkSettingsOutputBuilder {
    /// <p>The network settings.</p>
    pub fn network_settings(mut self, input: crate::types::NetworkSettings) -> Self {
        self.network_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network settings.</p>
    pub fn set_network_settings(mut self, input: ::std::option::Option<crate::types::NetworkSettings>) -> Self {
        self.network_settings = input;
        self
    }
    /// <p>The network settings.</p>
    pub fn get_network_settings(&self) -> &::std::option::Option<crate::types::NetworkSettings> {
        &self.network_settings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetNetworkSettingsOutput`](crate::operation::get_network_settings::GetNetworkSettingsOutput).
    pub fn build(self) -> crate::operation::get_network_settings::GetNetworkSettingsOutput {
        crate::operation::get_network_settings::GetNetworkSettingsOutput {
            network_settings: self.network_settings,
            _request_id: self._request_id,
        }
    }
}
