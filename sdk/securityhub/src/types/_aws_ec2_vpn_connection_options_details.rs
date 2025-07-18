// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>VPN connection options.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2VpnConnectionOptionsDetails {
    /// <p>Whether the VPN connection uses static routes only.</p>
    pub static_routes_only: ::std::option::Option<bool>,
    /// <p>The VPN tunnel options.</p>
    pub tunnel_options: ::std::option::Option<::std::vec::Vec<crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails>>,
}
impl AwsEc2VpnConnectionOptionsDetails {
    /// <p>Whether the VPN connection uses static routes only.</p>
    pub fn static_routes_only(&self) -> ::std::option::Option<bool> {
        self.static_routes_only
    }
    /// <p>The VPN tunnel options.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tunnel_options.is_none()`.
    pub fn tunnel_options(&self) -> &[crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails] {
        self.tunnel_options.as_deref().unwrap_or_default()
    }
}
impl AwsEc2VpnConnectionOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2VpnConnectionOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsEc2VpnConnectionOptionsDetailsBuilder {
        crate::types::builders::AwsEc2VpnConnectionOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2VpnConnectionOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2VpnConnectionOptionsDetailsBuilder {
    pub(crate) static_routes_only: ::std::option::Option<bool>,
    pub(crate) tunnel_options: ::std::option::Option<::std::vec::Vec<crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails>>,
}
impl AwsEc2VpnConnectionOptionsDetailsBuilder {
    /// <p>Whether the VPN connection uses static routes only.</p>
    pub fn static_routes_only(mut self, input: bool) -> Self {
        self.static_routes_only = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the VPN connection uses static routes only.</p>
    pub fn set_static_routes_only(mut self, input: ::std::option::Option<bool>) -> Self {
        self.static_routes_only = input;
        self
    }
    /// <p>Whether the VPN connection uses static routes only.</p>
    pub fn get_static_routes_only(&self) -> &::std::option::Option<bool> {
        &self.static_routes_only
    }
    /// Appends an item to `tunnel_options`.
    ///
    /// To override the contents of this collection use [`set_tunnel_options`](Self::set_tunnel_options).
    ///
    /// <p>The VPN tunnel options.</p>
    pub fn tunnel_options(mut self, input: crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails) -> Self {
        let mut v = self.tunnel_options.unwrap_or_default();
        v.push(input);
        self.tunnel_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPN tunnel options.</p>
    pub fn set_tunnel_options(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails>>,
    ) -> Self {
        self.tunnel_options = input;
        self
    }
    /// <p>The VPN tunnel options.</p>
    pub fn get_tunnel_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails>> {
        &self.tunnel_options
    }
    /// Consumes the builder and constructs a [`AwsEc2VpnConnectionOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsDetails).
    pub fn build(self) -> crate::types::AwsEc2VpnConnectionOptionsDetails {
        crate::types::AwsEc2VpnConnectionOptionsDetails {
            static_routes_only: self.static_routes_only,
            tunnel_options: self.tunnel_options,
        }
    }
}
