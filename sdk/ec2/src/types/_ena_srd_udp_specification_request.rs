// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures ENA Express for UDP network traffic from your launch template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnaSrdUdpSpecificationRequest {
    /// <p>Indicates whether UDP traffic uses ENA Express for your instance. To ensure that UDP traffic can use ENA Express when you launch an instance, you must also set <b>EnaSrdEnabled</b> in the <b>EnaSrdSpecificationRequest</b> to <code>true</code>.</p>
    pub ena_srd_udp_enabled: ::std::option::Option<bool>,
}
impl EnaSrdUdpSpecificationRequest {
    /// <p>Indicates whether UDP traffic uses ENA Express for your instance. To ensure that UDP traffic can use ENA Express when you launch an instance, you must also set <b>EnaSrdEnabled</b> in the <b>EnaSrdSpecificationRequest</b> to <code>true</code>.</p>
    pub fn ena_srd_udp_enabled(&self) -> ::std::option::Option<bool> {
        self.ena_srd_udp_enabled
    }
}
impl EnaSrdUdpSpecificationRequest {
    /// Creates a new builder-style object to manufacture [`EnaSrdUdpSpecificationRequest`](crate::types::EnaSrdUdpSpecificationRequest).
    pub fn builder() -> crate::types::builders::EnaSrdUdpSpecificationRequestBuilder {
        crate::types::builders::EnaSrdUdpSpecificationRequestBuilder::default()
    }
}

/// A builder for [`EnaSrdUdpSpecificationRequest`](crate::types::EnaSrdUdpSpecificationRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnaSrdUdpSpecificationRequestBuilder {
    pub(crate) ena_srd_udp_enabled: ::std::option::Option<bool>,
}
impl EnaSrdUdpSpecificationRequestBuilder {
    /// <p>Indicates whether UDP traffic uses ENA Express for your instance. To ensure that UDP traffic can use ENA Express when you launch an instance, you must also set <b>EnaSrdEnabled</b> in the <b>EnaSrdSpecificationRequest</b> to <code>true</code>.</p>
    pub fn ena_srd_udp_enabled(mut self, input: bool) -> Self {
        self.ena_srd_udp_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether UDP traffic uses ENA Express for your instance. To ensure that UDP traffic can use ENA Express when you launch an instance, you must also set <b>EnaSrdEnabled</b> in the <b>EnaSrdSpecificationRequest</b> to <code>true</code>.</p>
    pub fn set_ena_srd_udp_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ena_srd_udp_enabled = input;
        self
    }
    /// <p>Indicates whether UDP traffic uses ENA Express for your instance. To ensure that UDP traffic can use ENA Express when you launch an instance, you must also set <b>EnaSrdEnabled</b> in the <b>EnaSrdSpecificationRequest</b> to <code>true</code>.</p>
    pub fn get_ena_srd_udp_enabled(&self) -> &::std::option::Option<bool> {
        &self.ena_srd_udp_enabled
    }
    /// Consumes the builder and constructs a [`EnaSrdUdpSpecificationRequest`](crate::types::EnaSrdUdpSpecificationRequest).
    pub fn build(self) -> crate::types::EnaSrdUdpSpecificationRequest {
        crate::types::EnaSrdUdpSpecificationRequest {
            ena_srd_udp_enabled: self.ena_srd_udp_enabled,
        }
    }
}
