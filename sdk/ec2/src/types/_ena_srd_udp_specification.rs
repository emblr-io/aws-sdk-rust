// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ENA Express is compatible with both TCP and UDP transport protocols. When it's enabled, TCP traffic automatically uses it. However, some UDP-based applications are designed to handle network packets that are out of order, without a need for retransmission, such as live video broadcasting or other near-real-time applications. For UDP traffic, you can specify whether to use ENA Express, based on your application environment needs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnaSrdUdpSpecification {
    /// <p>Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express.</p>
    pub ena_srd_udp_enabled: ::std::option::Option<bool>,
}
impl EnaSrdUdpSpecification {
    /// <p>Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express.</p>
    pub fn ena_srd_udp_enabled(&self) -> ::std::option::Option<bool> {
        self.ena_srd_udp_enabled
    }
}
impl EnaSrdUdpSpecification {
    /// Creates a new builder-style object to manufacture [`EnaSrdUdpSpecification`](crate::types::EnaSrdUdpSpecification).
    pub fn builder() -> crate::types::builders::EnaSrdUdpSpecificationBuilder {
        crate::types::builders::EnaSrdUdpSpecificationBuilder::default()
    }
}

/// A builder for [`EnaSrdUdpSpecification`](crate::types::EnaSrdUdpSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnaSrdUdpSpecificationBuilder {
    pub(crate) ena_srd_udp_enabled: ::std::option::Option<bool>,
}
impl EnaSrdUdpSpecificationBuilder {
    /// <p>Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express.</p>
    pub fn ena_srd_udp_enabled(mut self, input: bool) -> Self {
        self.ena_srd_udp_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express.</p>
    pub fn set_ena_srd_udp_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ena_srd_udp_enabled = input;
        self
    }
    /// <p>Indicates whether UDP traffic to and from the instance uses ENA Express. To specify this setting, you must first enable ENA Express.</p>
    pub fn get_ena_srd_udp_enabled(&self) -> &::std::option::Option<bool> {
        &self.ena_srd_udp_enabled
    }
    /// Consumes the builder and constructs a [`EnaSrdUdpSpecification`](crate::types::EnaSrdUdpSpecification).
    pub fn build(self) -> crate::types::EnaSrdUdpSpecification {
        crate::types::EnaSrdUdpSpecification {
            ena_srd_udp_enabled: self.ena_srd_udp_enabled,
        }
    }
}
