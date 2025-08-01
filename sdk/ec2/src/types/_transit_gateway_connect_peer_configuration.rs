// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Connect peer details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TransitGatewayConnectPeerConfiguration {
    /// <p>The Connect peer IP address on the transit gateway side of the tunnel.</p>
    pub transit_gateway_address: ::std::option::Option<::std::string::String>,
    /// <p>The Connect peer IP address on the appliance side of the tunnel.</p>
    pub peer_address: ::std::option::Option<::std::string::String>,
    /// <p>The range of interior BGP peer IP addresses.</p>
    pub inside_cidr_blocks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The tunnel protocol.</p>
    pub protocol: ::std::option::Option<crate::types::ProtocolValue>,
    /// <p>The BGP configuration details.</p>
    pub bgp_configurations: ::std::option::Option<::std::vec::Vec<crate::types::TransitGatewayAttachmentBgpConfiguration>>,
}
impl TransitGatewayConnectPeerConfiguration {
    /// <p>The Connect peer IP address on the transit gateway side of the tunnel.</p>
    pub fn transit_gateway_address(&self) -> ::std::option::Option<&str> {
        self.transit_gateway_address.as_deref()
    }
    /// <p>The Connect peer IP address on the appliance side of the tunnel.</p>
    pub fn peer_address(&self) -> ::std::option::Option<&str> {
        self.peer_address.as_deref()
    }
    /// <p>The range of interior BGP peer IP addresses.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inside_cidr_blocks.is_none()`.
    pub fn inside_cidr_blocks(&self) -> &[::std::string::String] {
        self.inside_cidr_blocks.as_deref().unwrap_or_default()
    }
    /// <p>The tunnel protocol.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::ProtocolValue> {
        self.protocol.as_ref()
    }
    /// <p>The BGP configuration details.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bgp_configurations.is_none()`.
    pub fn bgp_configurations(&self) -> &[crate::types::TransitGatewayAttachmentBgpConfiguration] {
        self.bgp_configurations.as_deref().unwrap_or_default()
    }
}
impl TransitGatewayConnectPeerConfiguration {
    /// Creates a new builder-style object to manufacture [`TransitGatewayConnectPeerConfiguration`](crate::types::TransitGatewayConnectPeerConfiguration).
    pub fn builder() -> crate::types::builders::TransitGatewayConnectPeerConfigurationBuilder {
        crate::types::builders::TransitGatewayConnectPeerConfigurationBuilder::default()
    }
}

/// A builder for [`TransitGatewayConnectPeerConfiguration`](crate::types::TransitGatewayConnectPeerConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TransitGatewayConnectPeerConfigurationBuilder {
    pub(crate) transit_gateway_address: ::std::option::Option<::std::string::String>,
    pub(crate) peer_address: ::std::option::Option<::std::string::String>,
    pub(crate) inside_cidr_blocks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) protocol: ::std::option::Option<crate::types::ProtocolValue>,
    pub(crate) bgp_configurations: ::std::option::Option<::std::vec::Vec<crate::types::TransitGatewayAttachmentBgpConfiguration>>,
}
impl TransitGatewayConnectPeerConfigurationBuilder {
    /// <p>The Connect peer IP address on the transit gateway side of the tunnel.</p>
    pub fn transit_gateway_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transit_gateway_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Connect peer IP address on the transit gateway side of the tunnel.</p>
    pub fn set_transit_gateway_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transit_gateway_address = input;
        self
    }
    /// <p>The Connect peer IP address on the transit gateway side of the tunnel.</p>
    pub fn get_transit_gateway_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.transit_gateway_address
    }
    /// <p>The Connect peer IP address on the appliance side of the tunnel.</p>
    pub fn peer_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.peer_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Connect peer IP address on the appliance side of the tunnel.</p>
    pub fn set_peer_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.peer_address = input;
        self
    }
    /// <p>The Connect peer IP address on the appliance side of the tunnel.</p>
    pub fn get_peer_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.peer_address
    }
    /// Appends an item to `inside_cidr_blocks`.
    ///
    /// To override the contents of this collection use [`set_inside_cidr_blocks`](Self::set_inside_cidr_blocks).
    ///
    /// <p>The range of interior BGP peer IP addresses.</p>
    pub fn inside_cidr_blocks(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.inside_cidr_blocks.unwrap_or_default();
        v.push(input.into());
        self.inside_cidr_blocks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The range of interior BGP peer IP addresses.</p>
    pub fn set_inside_cidr_blocks(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inside_cidr_blocks = input;
        self
    }
    /// <p>The range of interior BGP peer IP addresses.</p>
    pub fn get_inside_cidr_blocks(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.inside_cidr_blocks
    }
    /// <p>The tunnel protocol.</p>
    pub fn protocol(mut self, input: crate::types::ProtocolValue) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tunnel protocol.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::ProtocolValue>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The tunnel protocol.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::ProtocolValue> {
        &self.protocol
    }
    /// Appends an item to `bgp_configurations`.
    ///
    /// To override the contents of this collection use [`set_bgp_configurations`](Self::set_bgp_configurations).
    ///
    /// <p>The BGP configuration details.</p>
    pub fn bgp_configurations(mut self, input: crate::types::TransitGatewayAttachmentBgpConfiguration) -> Self {
        let mut v = self.bgp_configurations.unwrap_or_default();
        v.push(input);
        self.bgp_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The BGP configuration details.</p>
    pub fn set_bgp_configurations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::TransitGatewayAttachmentBgpConfiguration>>,
    ) -> Self {
        self.bgp_configurations = input;
        self
    }
    /// <p>The BGP configuration details.</p>
    pub fn get_bgp_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TransitGatewayAttachmentBgpConfiguration>> {
        &self.bgp_configurations
    }
    /// Consumes the builder and constructs a [`TransitGatewayConnectPeerConfiguration`](crate::types::TransitGatewayConnectPeerConfiguration).
    pub fn build(self) -> crate::types::TransitGatewayConnectPeerConfiguration {
        crate::types::TransitGatewayConnectPeerConfiguration {
            transit_gateway_address: self.transit_gateway_address,
            peer_address: self.peer_address,
            inside_cidr_blocks: self.inside_cidr_blocks,
            protocol: self.protocol,
            bgp_configurations: self.bgp_configurations,
        }
    }
}
