// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the networking features of the instance type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkInfo {
    /// <p>The network performance.</p>
    pub network_performance: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of network interfaces for the instance type.</p>
    pub maximum_network_interfaces: ::std::option::Option<i32>,
    /// <p>The maximum number of physical network cards that can be allocated to the instance.</p>
    pub maximum_network_cards: ::std::option::Option<i32>,
    /// <p>The index of the default network card, starting at 0.</p>
    pub default_network_card_index: ::std::option::Option<i32>,
    /// <p>Describes the network cards for the instance type.</p>
    pub network_cards: ::std::option::Option<::std::vec::Vec<crate::types::NetworkCardInfo>>,
    /// <p>The maximum number of IPv4 addresses per network interface.</p>
    pub ipv4_addresses_per_interface: ::std::option::Option<i32>,
    /// <p>The maximum number of IPv6 addresses per network interface.</p>
    pub ipv6_addresses_per_interface: ::std::option::Option<i32>,
    /// <p>Indicates whether IPv6 is supported.</p>
    pub ipv6_supported: ::std::option::Option<bool>,
    /// <p>Indicates whether Elastic Network Adapter (ENA) is supported.</p>
    pub ena_support: ::std::option::Option<crate::types::EnaSupport>,
    /// <p>Indicates whether Elastic Fabric Adapter (EFA) is supported.</p>
    pub efa_supported: ::std::option::Option<bool>,
    /// <p>Describes the Elastic Fabric Adapters for the instance type.</p>
    pub efa_info: ::std::option::Option<crate::types::EfaInfo>,
    /// <p>Indicates whether the instance type automatically encrypts in-transit traffic between instances.</p>
    pub encryption_in_transit_supported: ::std::option::Option<bool>,
    /// <p>Indicates whether the instance type supports ENA Express. ENA Express uses Amazon Web Services Scalable Reliable Datagram (SRD) technology to increase the maximum bandwidth used per stream and minimize tail latency of network traffic between EC2 instances.</p>
    pub ena_srd_supported: ::std::option::Option<bool>,
    /// <p>A list of valid settings for configurable bandwidth weighting for the instance type, if supported.</p>
    pub bandwidth_weightings: ::std::option::Option<::std::vec::Vec<crate::types::BandwidthWeightingType>>,
    /// <p>Indicates whether changing the number of ENA queues is supported.</p>
    pub flexible_ena_queues_support: ::std::option::Option<crate::types::FlexibleEnaQueuesSupport>,
}
impl NetworkInfo {
    /// <p>The network performance.</p>
    pub fn network_performance(&self) -> ::std::option::Option<&str> {
        self.network_performance.as_deref()
    }
    /// <p>The maximum number of network interfaces for the instance type.</p>
    pub fn maximum_network_interfaces(&self) -> ::std::option::Option<i32> {
        self.maximum_network_interfaces
    }
    /// <p>The maximum number of physical network cards that can be allocated to the instance.</p>
    pub fn maximum_network_cards(&self) -> ::std::option::Option<i32> {
        self.maximum_network_cards
    }
    /// <p>The index of the default network card, starting at 0.</p>
    pub fn default_network_card_index(&self) -> ::std::option::Option<i32> {
        self.default_network_card_index
    }
    /// <p>Describes the network cards for the instance type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_cards.is_none()`.
    pub fn network_cards(&self) -> &[crate::types::NetworkCardInfo] {
        self.network_cards.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of IPv4 addresses per network interface.</p>
    pub fn ipv4_addresses_per_interface(&self) -> ::std::option::Option<i32> {
        self.ipv4_addresses_per_interface
    }
    /// <p>The maximum number of IPv6 addresses per network interface.</p>
    pub fn ipv6_addresses_per_interface(&self) -> ::std::option::Option<i32> {
        self.ipv6_addresses_per_interface
    }
    /// <p>Indicates whether IPv6 is supported.</p>
    pub fn ipv6_supported(&self) -> ::std::option::Option<bool> {
        self.ipv6_supported
    }
    /// <p>Indicates whether Elastic Network Adapter (ENA) is supported.</p>
    pub fn ena_support(&self) -> ::std::option::Option<&crate::types::EnaSupport> {
        self.ena_support.as_ref()
    }
    /// <p>Indicates whether Elastic Fabric Adapter (EFA) is supported.</p>
    pub fn efa_supported(&self) -> ::std::option::Option<bool> {
        self.efa_supported
    }
    /// <p>Describes the Elastic Fabric Adapters for the instance type.</p>
    pub fn efa_info(&self) -> ::std::option::Option<&crate::types::EfaInfo> {
        self.efa_info.as_ref()
    }
    /// <p>Indicates whether the instance type automatically encrypts in-transit traffic between instances.</p>
    pub fn encryption_in_transit_supported(&self) -> ::std::option::Option<bool> {
        self.encryption_in_transit_supported
    }
    /// <p>Indicates whether the instance type supports ENA Express. ENA Express uses Amazon Web Services Scalable Reliable Datagram (SRD) technology to increase the maximum bandwidth used per stream and minimize tail latency of network traffic between EC2 instances.</p>
    pub fn ena_srd_supported(&self) -> ::std::option::Option<bool> {
        self.ena_srd_supported
    }
    /// <p>A list of valid settings for configurable bandwidth weighting for the instance type, if supported.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bandwidth_weightings.is_none()`.
    pub fn bandwidth_weightings(&self) -> &[crate::types::BandwidthWeightingType] {
        self.bandwidth_weightings.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether changing the number of ENA queues is supported.</p>
    pub fn flexible_ena_queues_support(&self) -> ::std::option::Option<&crate::types::FlexibleEnaQueuesSupport> {
        self.flexible_ena_queues_support.as_ref()
    }
}
impl NetworkInfo {
    /// Creates a new builder-style object to manufacture [`NetworkInfo`](crate::types::NetworkInfo).
    pub fn builder() -> crate::types::builders::NetworkInfoBuilder {
        crate::types::builders::NetworkInfoBuilder::default()
    }
}

/// A builder for [`NetworkInfo`](crate::types::NetworkInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkInfoBuilder {
    pub(crate) network_performance: ::std::option::Option<::std::string::String>,
    pub(crate) maximum_network_interfaces: ::std::option::Option<i32>,
    pub(crate) maximum_network_cards: ::std::option::Option<i32>,
    pub(crate) default_network_card_index: ::std::option::Option<i32>,
    pub(crate) network_cards: ::std::option::Option<::std::vec::Vec<crate::types::NetworkCardInfo>>,
    pub(crate) ipv4_addresses_per_interface: ::std::option::Option<i32>,
    pub(crate) ipv6_addresses_per_interface: ::std::option::Option<i32>,
    pub(crate) ipv6_supported: ::std::option::Option<bool>,
    pub(crate) ena_support: ::std::option::Option<crate::types::EnaSupport>,
    pub(crate) efa_supported: ::std::option::Option<bool>,
    pub(crate) efa_info: ::std::option::Option<crate::types::EfaInfo>,
    pub(crate) encryption_in_transit_supported: ::std::option::Option<bool>,
    pub(crate) ena_srd_supported: ::std::option::Option<bool>,
    pub(crate) bandwidth_weightings: ::std::option::Option<::std::vec::Vec<crate::types::BandwidthWeightingType>>,
    pub(crate) flexible_ena_queues_support: ::std::option::Option<crate::types::FlexibleEnaQueuesSupport>,
}
impl NetworkInfoBuilder {
    /// <p>The network performance.</p>
    pub fn network_performance(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_performance = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The network performance.</p>
    pub fn set_network_performance(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_performance = input;
        self
    }
    /// <p>The network performance.</p>
    pub fn get_network_performance(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_performance
    }
    /// <p>The maximum number of network interfaces for the instance type.</p>
    pub fn maximum_network_interfaces(mut self, input: i32) -> Self {
        self.maximum_network_interfaces = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of network interfaces for the instance type.</p>
    pub fn set_maximum_network_interfaces(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_network_interfaces = input;
        self
    }
    /// <p>The maximum number of network interfaces for the instance type.</p>
    pub fn get_maximum_network_interfaces(&self) -> &::std::option::Option<i32> {
        &self.maximum_network_interfaces
    }
    /// <p>The maximum number of physical network cards that can be allocated to the instance.</p>
    pub fn maximum_network_cards(mut self, input: i32) -> Self {
        self.maximum_network_cards = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of physical network cards that can be allocated to the instance.</p>
    pub fn set_maximum_network_cards(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_network_cards = input;
        self
    }
    /// <p>The maximum number of physical network cards that can be allocated to the instance.</p>
    pub fn get_maximum_network_cards(&self) -> &::std::option::Option<i32> {
        &self.maximum_network_cards
    }
    /// <p>The index of the default network card, starting at 0.</p>
    pub fn default_network_card_index(mut self, input: i32) -> Self {
        self.default_network_card_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The index of the default network card, starting at 0.</p>
    pub fn set_default_network_card_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.default_network_card_index = input;
        self
    }
    /// <p>The index of the default network card, starting at 0.</p>
    pub fn get_default_network_card_index(&self) -> &::std::option::Option<i32> {
        &self.default_network_card_index
    }
    /// Appends an item to `network_cards`.
    ///
    /// To override the contents of this collection use [`set_network_cards`](Self::set_network_cards).
    ///
    /// <p>Describes the network cards for the instance type.</p>
    pub fn network_cards(mut self, input: crate::types::NetworkCardInfo) -> Self {
        let mut v = self.network_cards.unwrap_or_default();
        v.push(input);
        self.network_cards = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the network cards for the instance type.</p>
    pub fn set_network_cards(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkCardInfo>>) -> Self {
        self.network_cards = input;
        self
    }
    /// <p>Describes the network cards for the instance type.</p>
    pub fn get_network_cards(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkCardInfo>> {
        &self.network_cards
    }
    /// <p>The maximum number of IPv4 addresses per network interface.</p>
    pub fn ipv4_addresses_per_interface(mut self, input: i32) -> Self {
        self.ipv4_addresses_per_interface = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of IPv4 addresses per network interface.</p>
    pub fn set_ipv4_addresses_per_interface(mut self, input: ::std::option::Option<i32>) -> Self {
        self.ipv4_addresses_per_interface = input;
        self
    }
    /// <p>The maximum number of IPv4 addresses per network interface.</p>
    pub fn get_ipv4_addresses_per_interface(&self) -> &::std::option::Option<i32> {
        &self.ipv4_addresses_per_interface
    }
    /// <p>The maximum number of IPv6 addresses per network interface.</p>
    pub fn ipv6_addresses_per_interface(mut self, input: i32) -> Self {
        self.ipv6_addresses_per_interface = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of IPv6 addresses per network interface.</p>
    pub fn set_ipv6_addresses_per_interface(mut self, input: ::std::option::Option<i32>) -> Self {
        self.ipv6_addresses_per_interface = input;
        self
    }
    /// <p>The maximum number of IPv6 addresses per network interface.</p>
    pub fn get_ipv6_addresses_per_interface(&self) -> &::std::option::Option<i32> {
        &self.ipv6_addresses_per_interface
    }
    /// <p>Indicates whether IPv6 is supported.</p>
    pub fn ipv6_supported(mut self, input: bool) -> Self {
        self.ipv6_supported = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether IPv6 is supported.</p>
    pub fn set_ipv6_supported(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ipv6_supported = input;
        self
    }
    /// <p>Indicates whether IPv6 is supported.</p>
    pub fn get_ipv6_supported(&self) -> &::std::option::Option<bool> {
        &self.ipv6_supported
    }
    /// <p>Indicates whether Elastic Network Adapter (ENA) is supported.</p>
    pub fn ena_support(mut self, input: crate::types::EnaSupport) -> Self {
        self.ena_support = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Elastic Network Adapter (ENA) is supported.</p>
    pub fn set_ena_support(mut self, input: ::std::option::Option<crate::types::EnaSupport>) -> Self {
        self.ena_support = input;
        self
    }
    /// <p>Indicates whether Elastic Network Adapter (ENA) is supported.</p>
    pub fn get_ena_support(&self) -> &::std::option::Option<crate::types::EnaSupport> {
        &self.ena_support
    }
    /// <p>Indicates whether Elastic Fabric Adapter (EFA) is supported.</p>
    pub fn efa_supported(mut self, input: bool) -> Self {
        self.efa_supported = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Elastic Fabric Adapter (EFA) is supported.</p>
    pub fn set_efa_supported(mut self, input: ::std::option::Option<bool>) -> Self {
        self.efa_supported = input;
        self
    }
    /// <p>Indicates whether Elastic Fabric Adapter (EFA) is supported.</p>
    pub fn get_efa_supported(&self) -> &::std::option::Option<bool> {
        &self.efa_supported
    }
    /// <p>Describes the Elastic Fabric Adapters for the instance type.</p>
    pub fn efa_info(mut self, input: crate::types::EfaInfo) -> Self {
        self.efa_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the Elastic Fabric Adapters for the instance type.</p>
    pub fn set_efa_info(mut self, input: ::std::option::Option<crate::types::EfaInfo>) -> Self {
        self.efa_info = input;
        self
    }
    /// <p>Describes the Elastic Fabric Adapters for the instance type.</p>
    pub fn get_efa_info(&self) -> &::std::option::Option<crate::types::EfaInfo> {
        &self.efa_info
    }
    /// <p>Indicates whether the instance type automatically encrypts in-transit traffic between instances.</p>
    pub fn encryption_in_transit_supported(mut self, input: bool) -> Self {
        self.encryption_in_transit_supported = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the instance type automatically encrypts in-transit traffic between instances.</p>
    pub fn set_encryption_in_transit_supported(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encryption_in_transit_supported = input;
        self
    }
    /// <p>Indicates whether the instance type automatically encrypts in-transit traffic between instances.</p>
    pub fn get_encryption_in_transit_supported(&self) -> &::std::option::Option<bool> {
        &self.encryption_in_transit_supported
    }
    /// <p>Indicates whether the instance type supports ENA Express. ENA Express uses Amazon Web Services Scalable Reliable Datagram (SRD) technology to increase the maximum bandwidth used per stream and minimize tail latency of network traffic between EC2 instances.</p>
    pub fn ena_srd_supported(mut self, input: bool) -> Self {
        self.ena_srd_supported = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the instance type supports ENA Express. ENA Express uses Amazon Web Services Scalable Reliable Datagram (SRD) technology to increase the maximum bandwidth used per stream and minimize tail latency of network traffic between EC2 instances.</p>
    pub fn set_ena_srd_supported(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ena_srd_supported = input;
        self
    }
    /// <p>Indicates whether the instance type supports ENA Express. ENA Express uses Amazon Web Services Scalable Reliable Datagram (SRD) technology to increase the maximum bandwidth used per stream and minimize tail latency of network traffic between EC2 instances.</p>
    pub fn get_ena_srd_supported(&self) -> &::std::option::Option<bool> {
        &self.ena_srd_supported
    }
    /// Appends an item to `bandwidth_weightings`.
    ///
    /// To override the contents of this collection use [`set_bandwidth_weightings`](Self::set_bandwidth_weightings).
    ///
    /// <p>A list of valid settings for configurable bandwidth weighting for the instance type, if supported.</p>
    pub fn bandwidth_weightings(mut self, input: crate::types::BandwidthWeightingType) -> Self {
        let mut v = self.bandwidth_weightings.unwrap_or_default();
        v.push(input);
        self.bandwidth_weightings = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of valid settings for configurable bandwidth weighting for the instance type, if supported.</p>
    pub fn set_bandwidth_weightings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BandwidthWeightingType>>) -> Self {
        self.bandwidth_weightings = input;
        self
    }
    /// <p>A list of valid settings for configurable bandwidth weighting for the instance type, if supported.</p>
    pub fn get_bandwidth_weightings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BandwidthWeightingType>> {
        &self.bandwidth_weightings
    }
    /// <p>Indicates whether changing the number of ENA queues is supported.</p>
    pub fn flexible_ena_queues_support(mut self, input: crate::types::FlexibleEnaQueuesSupport) -> Self {
        self.flexible_ena_queues_support = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether changing the number of ENA queues is supported.</p>
    pub fn set_flexible_ena_queues_support(mut self, input: ::std::option::Option<crate::types::FlexibleEnaQueuesSupport>) -> Self {
        self.flexible_ena_queues_support = input;
        self
    }
    /// <p>Indicates whether changing the number of ENA queues is supported.</p>
    pub fn get_flexible_ena_queues_support(&self) -> &::std::option::Option<crate::types::FlexibleEnaQueuesSupport> {
        &self.flexible_ena_queues_support
    }
    /// Consumes the builder and constructs a [`NetworkInfo`](crate::types::NetworkInfo).
    pub fn build(self) -> crate::types::NetworkInfo {
        crate::types::NetworkInfo {
            network_performance: self.network_performance,
            maximum_network_interfaces: self.maximum_network_interfaces,
            maximum_network_cards: self.maximum_network_cards,
            default_network_card_index: self.default_network_card_index,
            network_cards: self.network_cards,
            ipv4_addresses_per_interface: self.ipv4_addresses_per_interface,
            ipv6_addresses_per_interface: self.ipv6_addresses_per_interface,
            ipv6_supported: self.ipv6_supported,
            ena_support: self.ena_support,
            efa_supported: self.efa_supported,
            efa_info: self.efa_info,
            encryption_in_transit_supported: self.encryption_in_transit_supported,
            ena_srd_supported: self.ena_srd_supported,
            bandwidth_weightings: self.bandwidth_weightings,
            flexible_ena_queues_support: self.flexible_ena_queues_support,
        }
    }
}
