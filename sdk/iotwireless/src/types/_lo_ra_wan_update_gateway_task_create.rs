// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>LoRaWANUpdateGatewayTaskCreate object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoRaWanUpdateGatewayTaskCreate {
    /// <p>The signature used to verify the update firmware.</p>
    pub update_signature: ::std::option::Option<::std::string::String>,
    /// <p>The CRC of the signature private key to check.</p>
    pub sig_key_crc: ::std::option::Option<i64>,
    /// <p>The version of the gateways that should receive the update.</p>
    pub current_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
    /// <p>The firmware version to update the gateway to.</p>
    pub update_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
}
impl LoRaWanUpdateGatewayTaskCreate {
    /// <p>The signature used to verify the update firmware.</p>
    pub fn update_signature(&self) -> ::std::option::Option<&str> {
        self.update_signature.as_deref()
    }
    /// <p>The CRC of the signature private key to check.</p>
    pub fn sig_key_crc(&self) -> ::std::option::Option<i64> {
        self.sig_key_crc
    }
    /// <p>The version of the gateways that should receive the update.</p>
    pub fn current_version(&self) -> ::std::option::Option<&crate::types::LoRaWanGatewayVersion> {
        self.current_version.as_ref()
    }
    /// <p>The firmware version to update the gateway to.</p>
    pub fn update_version(&self) -> ::std::option::Option<&crate::types::LoRaWanGatewayVersion> {
        self.update_version.as_ref()
    }
}
impl LoRaWanUpdateGatewayTaskCreate {
    /// Creates a new builder-style object to manufacture [`LoRaWanUpdateGatewayTaskCreate`](crate::types::LoRaWanUpdateGatewayTaskCreate).
    pub fn builder() -> crate::types::builders::LoRaWanUpdateGatewayTaskCreateBuilder {
        crate::types::builders::LoRaWanUpdateGatewayTaskCreateBuilder::default()
    }
}

/// A builder for [`LoRaWanUpdateGatewayTaskCreate`](crate::types::LoRaWanUpdateGatewayTaskCreate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoRaWanUpdateGatewayTaskCreateBuilder {
    pub(crate) update_signature: ::std::option::Option<::std::string::String>,
    pub(crate) sig_key_crc: ::std::option::Option<i64>,
    pub(crate) current_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
    pub(crate) update_version: ::std::option::Option<crate::types::LoRaWanGatewayVersion>,
}
impl LoRaWanUpdateGatewayTaskCreateBuilder {
    /// <p>The signature used to verify the update firmware.</p>
    pub fn update_signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.update_signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The signature used to verify the update firmware.</p>
    pub fn set_update_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.update_signature = input;
        self
    }
    /// <p>The signature used to verify the update firmware.</p>
    pub fn get_update_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.update_signature
    }
    /// <p>The CRC of the signature private key to check.</p>
    pub fn sig_key_crc(mut self, input: i64) -> Self {
        self.sig_key_crc = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CRC of the signature private key to check.</p>
    pub fn set_sig_key_crc(mut self, input: ::std::option::Option<i64>) -> Self {
        self.sig_key_crc = input;
        self
    }
    /// <p>The CRC of the signature private key to check.</p>
    pub fn get_sig_key_crc(&self) -> &::std::option::Option<i64> {
        &self.sig_key_crc
    }
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
    /// Consumes the builder and constructs a [`LoRaWanUpdateGatewayTaskCreate`](crate::types::LoRaWanUpdateGatewayTaskCreate).
    pub fn build(self) -> crate::types::LoRaWanUpdateGatewayTaskCreate {
        crate::types::LoRaWanUpdateGatewayTaskCreate {
            update_signature: self.update_signature,
            sig_key_crc: self.sig_key_crc,
            current_version: self.current_version,
            update_version: self.update_version,
        }
    }
}
