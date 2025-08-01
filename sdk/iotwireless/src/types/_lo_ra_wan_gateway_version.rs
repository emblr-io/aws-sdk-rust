// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>LoRaWANGatewayVersion object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoRaWanGatewayVersion {
    /// <p>The version of the wireless gateway firmware.</p>
    pub package_version: ::std::option::Option<::std::string::String>,
    /// <p>The model number of the wireless gateway.</p>
    pub model: ::std::option::Option<::std::string::String>,
    /// <p>The basic station version of the wireless gateway.</p>
    pub station: ::std::option::Option<::std::string::String>,
}
impl LoRaWanGatewayVersion {
    /// <p>The version of the wireless gateway firmware.</p>
    pub fn package_version(&self) -> ::std::option::Option<&str> {
        self.package_version.as_deref()
    }
    /// <p>The model number of the wireless gateway.</p>
    pub fn model(&self) -> ::std::option::Option<&str> {
        self.model.as_deref()
    }
    /// <p>The basic station version of the wireless gateway.</p>
    pub fn station(&self) -> ::std::option::Option<&str> {
        self.station.as_deref()
    }
}
impl LoRaWanGatewayVersion {
    /// Creates a new builder-style object to manufacture [`LoRaWanGatewayVersion`](crate::types::LoRaWanGatewayVersion).
    pub fn builder() -> crate::types::builders::LoRaWanGatewayVersionBuilder {
        crate::types::builders::LoRaWanGatewayVersionBuilder::default()
    }
}

/// A builder for [`LoRaWanGatewayVersion`](crate::types::LoRaWanGatewayVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoRaWanGatewayVersionBuilder {
    pub(crate) package_version: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<::std::string::String>,
    pub(crate) station: ::std::option::Option<::std::string::String>,
}
impl LoRaWanGatewayVersionBuilder {
    /// <p>The version of the wireless gateway firmware.</p>
    pub fn package_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the wireless gateway firmware.</p>
    pub fn set_package_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_version = input;
        self
    }
    /// <p>The version of the wireless gateway firmware.</p>
    pub fn get_package_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_version
    }
    /// <p>The model number of the wireless gateway.</p>
    pub fn model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model number of the wireless gateway.</p>
    pub fn set_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model = input;
        self
    }
    /// <p>The model number of the wireless gateway.</p>
    pub fn get_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.model
    }
    /// <p>The basic station version of the wireless gateway.</p>
    pub fn station(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.station = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The basic station version of the wireless gateway.</p>
    pub fn set_station(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.station = input;
        self
    }
    /// <p>The basic station version of the wireless gateway.</p>
    pub fn get_station(&self) -> &::std::option::Option<::std::string::String> {
        &self.station
    }
    /// Consumes the builder and constructs a [`LoRaWanGatewayVersion`](crate::types::LoRaWanGatewayVersion).
    pub fn build(self) -> crate::types::LoRaWanGatewayVersion {
        crate::types::LoRaWanGatewayVersion {
            package_version: self.package_version,
            model: self.model,
            station: self.station,
        }
    }
}
