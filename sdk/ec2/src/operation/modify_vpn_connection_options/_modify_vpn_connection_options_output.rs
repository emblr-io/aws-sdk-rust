// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyVpnConnectionOptionsOutput {
    /// <p>Information about the VPN connection.</p>
    pub vpn_connection: ::std::option::Option<crate::types::VpnConnection>,
    _request_id: Option<String>,
}
impl ModifyVpnConnectionOptionsOutput {
    /// <p>Information about the VPN connection.</p>
    pub fn vpn_connection(&self) -> ::std::option::Option<&crate::types::VpnConnection> {
        self.vpn_connection.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyVpnConnectionOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyVpnConnectionOptionsOutput {
    /// Creates a new builder-style object to manufacture [`ModifyVpnConnectionOptionsOutput`](crate::operation::modify_vpn_connection_options::ModifyVpnConnectionOptionsOutput).
    pub fn builder() -> crate::operation::modify_vpn_connection_options::builders::ModifyVpnConnectionOptionsOutputBuilder {
        crate::operation::modify_vpn_connection_options::builders::ModifyVpnConnectionOptionsOutputBuilder::default()
    }
}

/// A builder for [`ModifyVpnConnectionOptionsOutput`](crate::operation::modify_vpn_connection_options::ModifyVpnConnectionOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyVpnConnectionOptionsOutputBuilder {
    pub(crate) vpn_connection: ::std::option::Option<crate::types::VpnConnection>,
    _request_id: Option<String>,
}
impl ModifyVpnConnectionOptionsOutputBuilder {
    /// <p>Information about the VPN connection.</p>
    pub fn vpn_connection(mut self, input: crate::types::VpnConnection) -> Self {
        self.vpn_connection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the VPN connection.</p>
    pub fn set_vpn_connection(mut self, input: ::std::option::Option<crate::types::VpnConnection>) -> Self {
        self.vpn_connection = input;
        self
    }
    /// <p>Information about the VPN connection.</p>
    pub fn get_vpn_connection(&self) -> &::std::option::Option<crate::types::VpnConnection> {
        &self.vpn_connection
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyVpnConnectionOptionsOutput`](crate::operation::modify_vpn_connection_options::ModifyVpnConnectionOptionsOutput).
    pub fn build(self) -> crate::operation::modify_vpn_connection_options::ModifyVpnConnectionOptionsOutput {
        crate::operation::modify_vpn_connection_options::ModifyVpnConnectionOptionsOutput {
            vpn_connection: self.vpn_connection,
            _request_id: self._request_id,
        }
    }
}
