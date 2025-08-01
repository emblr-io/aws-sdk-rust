// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplaceVpnTunnelOutput {
    /// <p>Confirmation of replace tunnel operation.</p>
    pub r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ReplaceVpnTunnelOutput {
    /// <p>Confirmation of replace tunnel operation.</p>
    pub fn r#return(&self) -> ::std::option::Option<bool> {
        self.r#return
    }
}
impl ::aws_types::request_id::RequestId for ReplaceVpnTunnelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReplaceVpnTunnelOutput {
    /// Creates a new builder-style object to manufacture [`ReplaceVpnTunnelOutput`](crate::operation::replace_vpn_tunnel::ReplaceVpnTunnelOutput).
    pub fn builder() -> crate::operation::replace_vpn_tunnel::builders::ReplaceVpnTunnelOutputBuilder {
        crate::operation::replace_vpn_tunnel::builders::ReplaceVpnTunnelOutputBuilder::default()
    }
}

/// A builder for [`ReplaceVpnTunnelOutput`](crate::operation::replace_vpn_tunnel::ReplaceVpnTunnelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplaceVpnTunnelOutputBuilder {
    pub(crate) r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ReplaceVpnTunnelOutputBuilder {
    /// <p>Confirmation of replace tunnel operation.</p>
    pub fn r#return(mut self, input: bool) -> Self {
        self.r#return = ::std::option::Option::Some(input);
        self
    }
    /// <p>Confirmation of replace tunnel operation.</p>
    pub fn set_return(mut self, input: ::std::option::Option<bool>) -> Self {
        self.r#return = input;
        self
    }
    /// <p>Confirmation of replace tunnel operation.</p>
    pub fn get_return(&self) -> &::std::option::Option<bool> {
        &self.r#return
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReplaceVpnTunnelOutput`](crate::operation::replace_vpn_tunnel::ReplaceVpnTunnelOutput).
    pub fn build(self) -> crate::operation::replace_vpn_tunnel::ReplaceVpnTunnelOutput {
        crate::operation::replace_vpn_tunnel::ReplaceVpnTunnelOutput {
            r#return: self.r#return,
            _request_id: self._request_id,
        }
    }
}
