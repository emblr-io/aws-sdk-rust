// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a local gateway virtual interface.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LocalGatewayVirtualInterface {
    /// <p>The ID of the virtual interface.</p>
    pub local_gateway_virtual_interface_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the local gateway.</p>
    pub local_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the local gateway virtual interface group.</p>
    pub local_gateway_virtual_interface_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Number (ARN) of the local gateway virtual interface.</p>
    pub local_gateway_virtual_interface_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Outpost LAG ID.</p>
    pub outpost_lag_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the VLAN.</p>
    pub vlan: ::std::option::Option<i32>,
    /// <p>The local address.</p>
    pub local_address: ::std::option::Option<::std::string::String>,
    /// <p>The peer address.</p>
    pub peer_address: ::std::option::Option<::std::string::String>,
    /// <p>The Border Gateway Protocol (BGP) Autonomous System Number (ASN) of the local gateway.</p>
    pub local_bgp_asn: ::std::option::Option<i32>,
    /// <p>The peer BGP ASN.</p>
    pub peer_bgp_asn: ::std::option::Option<i32>,
    /// <p>The extended 32-bit ASN of the BGP peer for use with larger ASN values.</p>
    pub peer_bgp_asn_extended: ::std::option::Option<i64>,
    /// <p>The ID of the Amazon Web Services account that owns the local gateway virtual interface.</p>
    pub owner_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags assigned to the virtual interface.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The current state of the local gateway virtual interface.</p>
    pub configuration_state: ::std::option::Option<crate::types::LocalGatewayVirtualInterfaceConfigurationState>,
}
impl LocalGatewayVirtualInterface {
    /// <p>The ID of the virtual interface.</p>
    pub fn local_gateway_virtual_interface_id(&self) -> ::std::option::Option<&str> {
        self.local_gateway_virtual_interface_id.as_deref()
    }
    /// <p>The ID of the local gateway.</p>
    pub fn local_gateway_id(&self) -> ::std::option::Option<&str> {
        self.local_gateway_id.as_deref()
    }
    /// <p>The ID of the local gateway virtual interface group.</p>
    pub fn local_gateway_virtual_interface_group_id(&self) -> ::std::option::Option<&str> {
        self.local_gateway_virtual_interface_group_id.as_deref()
    }
    /// <p>The Amazon Resource Number (ARN) of the local gateway virtual interface.</p>
    pub fn local_gateway_virtual_interface_arn(&self) -> ::std::option::Option<&str> {
        self.local_gateway_virtual_interface_arn.as_deref()
    }
    /// <p>The Outpost LAG ID.</p>
    pub fn outpost_lag_id(&self) -> ::std::option::Option<&str> {
        self.outpost_lag_id.as_deref()
    }
    /// <p>The ID of the VLAN.</p>
    pub fn vlan(&self) -> ::std::option::Option<i32> {
        self.vlan
    }
    /// <p>The local address.</p>
    pub fn local_address(&self) -> ::std::option::Option<&str> {
        self.local_address.as_deref()
    }
    /// <p>The peer address.</p>
    pub fn peer_address(&self) -> ::std::option::Option<&str> {
        self.peer_address.as_deref()
    }
    /// <p>The Border Gateway Protocol (BGP) Autonomous System Number (ASN) of the local gateway.</p>
    pub fn local_bgp_asn(&self) -> ::std::option::Option<i32> {
        self.local_bgp_asn
    }
    /// <p>The peer BGP ASN.</p>
    pub fn peer_bgp_asn(&self) -> ::std::option::Option<i32> {
        self.peer_bgp_asn
    }
    /// <p>The extended 32-bit ASN of the BGP peer for use with larger ASN values.</p>
    pub fn peer_bgp_asn_extended(&self) -> ::std::option::Option<i64> {
        self.peer_bgp_asn_extended
    }
    /// <p>The ID of the Amazon Web Services account that owns the local gateway virtual interface.</p>
    pub fn owner_id(&self) -> ::std::option::Option<&str> {
        self.owner_id.as_deref()
    }
    /// <p>The tags assigned to the virtual interface.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The current state of the local gateway virtual interface.</p>
    pub fn configuration_state(&self) -> ::std::option::Option<&crate::types::LocalGatewayVirtualInterfaceConfigurationState> {
        self.configuration_state.as_ref()
    }
}
impl LocalGatewayVirtualInterface {
    /// Creates a new builder-style object to manufacture [`LocalGatewayVirtualInterface`](crate::types::LocalGatewayVirtualInterface).
    pub fn builder() -> crate::types::builders::LocalGatewayVirtualInterfaceBuilder {
        crate::types::builders::LocalGatewayVirtualInterfaceBuilder::default()
    }
}

/// A builder for [`LocalGatewayVirtualInterface`](crate::types::LocalGatewayVirtualInterface).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LocalGatewayVirtualInterfaceBuilder {
    pub(crate) local_gateway_virtual_interface_id: ::std::option::Option<::std::string::String>,
    pub(crate) local_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) local_gateway_virtual_interface_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) local_gateway_virtual_interface_arn: ::std::option::Option<::std::string::String>,
    pub(crate) outpost_lag_id: ::std::option::Option<::std::string::String>,
    pub(crate) vlan: ::std::option::Option<i32>,
    pub(crate) local_address: ::std::option::Option<::std::string::String>,
    pub(crate) peer_address: ::std::option::Option<::std::string::String>,
    pub(crate) local_bgp_asn: ::std::option::Option<i32>,
    pub(crate) peer_bgp_asn: ::std::option::Option<i32>,
    pub(crate) peer_bgp_asn_extended: ::std::option::Option<i64>,
    pub(crate) owner_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) configuration_state: ::std::option::Option<crate::types::LocalGatewayVirtualInterfaceConfigurationState>,
}
impl LocalGatewayVirtualInterfaceBuilder {
    /// <p>The ID of the virtual interface.</p>
    pub fn local_gateway_virtual_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual interface.</p>
    pub fn set_local_gateway_virtual_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_id = input;
        self
    }
    /// <p>The ID of the virtual interface.</p>
    pub fn get_local_gateway_virtual_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_virtual_interface_id
    }
    /// <p>The ID of the local gateway.</p>
    pub fn local_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the local gateway.</p>
    pub fn set_local_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_id = input;
        self
    }
    /// <p>The ID of the local gateway.</p>
    pub fn get_local_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_id
    }
    /// <p>The ID of the local gateway virtual interface group.</p>
    pub fn local_gateway_virtual_interface_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the local gateway virtual interface group.</p>
    pub fn set_local_gateway_virtual_interface_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_group_id = input;
        self
    }
    /// <p>The ID of the local gateway virtual interface group.</p>
    pub fn get_local_gateway_virtual_interface_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_virtual_interface_group_id
    }
    /// <p>The Amazon Resource Number (ARN) of the local gateway virtual interface.</p>
    pub fn local_gateway_virtual_interface_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the local gateway virtual interface.</p>
    pub fn set_local_gateway_virtual_interface_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_virtual_interface_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the local gateway virtual interface.</p>
    pub fn get_local_gateway_virtual_interface_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_virtual_interface_arn
    }
    /// <p>The Outpost LAG ID.</p>
    pub fn outpost_lag_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outpost_lag_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Outpost LAG ID.</p>
    pub fn set_outpost_lag_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outpost_lag_id = input;
        self
    }
    /// <p>The Outpost LAG ID.</p>
    pub fn get_outpost_lag_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.outpost_lag_id
    }
    /// <p>The ID of the VLAN.</p>
    pub fn vlan(mut self, input: i32) -> Self {
        self.vlan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the VLAN.</p>
    pub fn set_vlan(mut self, input: ::std::option::Option<i32>) -> Self {
        self.vlan = input;
        self
    }
    /// <p>The ID of the VLAN.</p>
    pub fn get_vlan(&self) -> &::std::option::Option<i32> {
        &self.vlan
    }
    /// <p>The local address.</p>
    pub fn local_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The local address.</p>
    pub fn set_local_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_address = input;
        self
    }
    /// <p>The local address.</p>
    pub fn get_local_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_address
    }
    /// <p>The peer address.</p>
    pub fn peer_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.peer_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The peer address.</p>
    pub fn set_peer_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.peer_address = input;
        self
    }
    /// <p>The peer address.</p>
    pub fn get_peer_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.peer_address
    }
    /// <p>The Border Gateway Protocol (BGP) Autonomous System Number (ASN) of the local gateway.</p>
    pub fn local_bgp_asn(mut self, input: i32) -> Self {
        self.local_bgp_asn = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Border Gateway Protocol (BGP) Autonomous System Number (ASN) of the local gateway.</p>
    pub fn set_local_bgp_asn(mut self, input: ::std::option::Option<i32>) -> Self {
        self.local_bgp_asn = input;
        self
    }
    /// <p>The Border Gateway Protocol (BGP) Autonomous System Number (ASN) of the local gateway.</p>
    pub fn get_local_bgp_asn(&self) -> &::std::option::Option<i32> {
        &self.local_bgp_asn
    }
    /// <p>The peer BGP ASN.</p>
    pub fn peer_bgp_asn(mut self, input: i32) -> Self {
        self.peer_bgp_asn = ::std::option::Option::Some(input);
        self
    }
    /// <p>The peer BGP ASN.</p>
    pub fn set_peer_bgp_asn(mut self, input: ::std::option::Option<i32>) -> Self {
        self.peer_bgp_asn = input;
        self
    }
    /// <p>The peer BGP ASN.</p>
    pub fn get_peer_bgp_asn(&self) -> &::std::option::Option<i32> {
        &self.peer_bgp_asn
    }
    /// <p>The extended 32-bit ASN of the BGP peer for use with larger ASN values.</p>
    pub fn peer_bgp_asn_extended(mut self, input: i64) -> Self {
        self.peer_bgp_asn_extended = ::std::option::Option::Some(input);
        self
    }
    /// <p>The extended 32-bit ASN of the BGP peer for use with larger ASN values.</p>
    pub fn set_peer_bgp_asn_extended(mut self, input: ::std::option::Option<i64>) -> Self {
        self.peer_bgp_asn_extended = input;
        self
    }
    /// <p>The extended 32-bit ASN of the BGP peer for use with larger ASN values.</p>
    pub fn get_peer_bgp_asn_extended(&self) -> &::std::option::Option<i64> {
        &self.peer_bgp_asn_extended
    }
    /// <p>The ID of the Amazon Web Services account that owns the local gateway virtual interface.</p>
    pub fn owner_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the local gateway virtual interface.</p>
    pub fn set_owner_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the local gateway virtual interface.</p>
    pub fn get_owner_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the virtual interface.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags assigned to the virtual interface.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the virtual interface.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The current state of the local gateway virtual interface.</p>
    pub fn configuration_state(mut self, input: crate::types::LocalGatewayVirtualInterfaceConfigurationState) -> Self {
        self.configuration_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the local gateway virtual interface.</p>
    pub fn set_configuration_state(mut self, input: ::std::option::Option<crate::types::LocalGatewayVirtualInterfaceConfigurationState>) -> Self {
        self.configuration_state = input;
        self
    }
    /// <p>The current state of the local gateway virtual interface.</p>
    pub fn get_configuration_state(&self) -> &::std::option::Option<crate::types::LocalGatewayVirtualInterfaceConfigurationState> {
        &self.configuration_state
    }
    /// Consumes the builder and constructs a [`LocalGatewayVirtualInterface`](crate::types::LocalGatewayVirtualInterface).
    pub fn build(self) -> crate::types::LocalGatewayVirtualInterface {
        crate::types::LocalGatewayVirtualInterface {
            local_gateway_virtual_interface_id: self.local_gateway_virtual_interface_id,
            local_gateway_id: self.local_gateway_id,
            local_gateway_virtual_interface_group_id: self.local_gateway_virtual_interface_group_id,
            local_gateway_virtual_interface_arn: self.local_gateway_virtual_interface_arn,
            outpost_lag_id: self.outpost_lag_id,
            vlan: self.vlan,
            local_address: self.local_address,
            peer_address: self.peer_address,
            local_bgp_asn: self.local_bgp_asn,
            peer_bgp_asn: self.peer_bgp_asn,
            peer_bgp_asn_extended: self.peer_bgp_asn_extended,
            owner_id: self.owner_id,
            tags: self.tags,
            configuration_state: self.configuration_state,
        }
    }
}
