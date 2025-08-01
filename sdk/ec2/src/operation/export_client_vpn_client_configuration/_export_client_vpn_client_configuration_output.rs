// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportClientVpnClientConfigurationOutput {
    /// <p>The contents of the Client VPN endpoint configuration file.</p>
    pub client_configuration: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportClientVpnClientConfigurationOutput {
    /// <p>The contents of the Client VPN endpoint configuration file.</p>
    pub fn client_configuration(&self) -> ::std::option::Option<&str> {
        self.client_configuration.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ExportClientVpnClientConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExportClientVpnClientConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`ExportClientVpnClientConfigurationOutput`](crate::operation::export_client_vpn_client_configuration::ExportClientVpnClientConfigurationOutput).
    pub fn builder() -> crate::operation::export_client_vpn_client_configuration::builders::ExportClientVpnClientConfigurationOutputBuilder {
        crate::operation::export_client_vpn_client_configuration::builders::ExportClientVpnClientConfigurationOutputBuilder::default()
    }
}

/// A builder for [`ExportClientVpnClientConfigurationOutput`](crate::operation::export_client_vpn_client_configuration::ExportClientVpnClientConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportClientVpnClientConfigurationOutputBuilder {
    pub(crate) client_configuration: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportClientVpnClientConfigurationOutputBuilder {
    /// <p>The contents of the Client VPN endpoint configuration file.</p>
    pub fn client_configuration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_configuration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contents of the Client VPN endpoint configuration file.</p>
    pub fn set_client_configuration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_configuration = input;
        self
    }
    /// <p>The contents of the Client VPN endpoint configuration file.</p>
    pub fn get_client_configuration(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ExportClientVpnClientConfigurationOutput`](crate::operation::export_client_vpn_client_configuration::ExportClientVpnClientConfigurationOutput).
    pub fn build(self) -> crate::operation::export_client_vpn_client_configuration::ExportClientVpnClientConfigurationOutput {
        crate::operation::export_client_vpn_client_configuration::ExportClientVpnClientConfigurationOutput {
            client_configuration: self.client_configuration,
            _request_id: self._request_id,
        }
    }
}
