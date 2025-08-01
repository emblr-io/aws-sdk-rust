// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>LoRaWANUpdateGatewayTaskEntry object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoRaWanUpdateGatewayTaskEntry {
    /// <p>The version of the gateways that should receive the update.</p>
    pub current_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
    /// <p>The firmware version to update the gateway to.</p>
    pub update_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
}
impl LoRaWanUpdateGatewayTaskEntry {
    /// <p>The version of the gateways that should receive the update.</p>
    pub fn current_version(&self) -> ::std::option::Option<&crate::types::LoRaWanGatewayVersion> {
        self.current_version.as_ref()
    }
    /// <p>The firmware version to update the gateway to.</p>
    pub fn update_version(&self) -> ::std::option::Option<&crate::types::LoRaWanGatewayVersion> {
        self.update_version.as_ref()
    }
}
impl LoRaWanUpdateGatewayTaskEntry {
    /// Creates a new builder-style object to manufacture [`LoRaWanUpdateGatewayTaskEntry`](crate::types::LoRaWanUpdateGatewayTaskEntry).
    pub fn builder() -> crate::types::builders::LoRaWanUpdateGatewayTaskEntryBuilder {
        crate::types::builders::LoRaWanUpdateGatewayTaskEntryBuilder::default()
    }
}

/// A builder for [`LoRaWanUpdateGatewayTaskEntry`](crate::types::LoRaWanUpdateGatewayTaskEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoRaWanUpdateGatewayTaskEntryBuilder {
    pub(crate) current_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
    pub(crate) update_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
}
impl LoRaWanUpdateGatewayTaskEntryBuilder {
    /// <p>The version of the gateways that should receive the update.</p>
    pub fn current_version(mut self, input: crate::types::LoRaWanGatewayVersion) -> Self {
        self.current_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the gateways that should receive the update.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<crate::types::LoRaWanGatewayVersion>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The version of the gateways that should receive the update.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<crate::types::LoRaWanGatewayVersion> {
        &self.current_version
    }
    /// <p>The firmware version to update the gateway to.</p>
    pub fn update_version(mut self, input: crate::types::LoRaWanGatewayVersion) -> Self {
        self.update_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The firmware version to update the gateway to.</p>
    pub fn set_update_version(mut self, input: ::std::option::Option<crate::types::LoRaWanGatewayVersion>) -> Self {
        self.update_version = input;
        self
    }
    /// <p>The firmware version to update the gateway to.</p>
    pub fn get_update_version(&self) -> &::std::option::Option<crate::types::LoRaWanGatewayVersion> {
        &self.update_version
    }
    /// Consumes the builder and constructs a [`LoRaWanUpdateGatewayTaskEntry`](crate::types::LoRaWanUpdateGatewayTaskEntry).
    pub fn build(self) -> crate::types::LoRaWanUpdateGatewayTaskEntry {
        crate::types::LoRaWanUpdateGatewayTaskEntry {
            current_version: self.current_version,
            update_version: self.update_version,
        }
    }
}
