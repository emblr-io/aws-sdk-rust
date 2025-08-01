// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Use these settings to insert a DVB Network Information Table (NIT) in the transport stream of this output.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DvbNitSettings {
    /// The numeric value placed in the Network Information Table (NIT).
    pub network_id: ::std::option::Option<i32>,
    /// The network name text placed in the network_name_descriptor inside the Network Information Table. Maximum length is 256 characters.
    pub network_name: ::std::option::Option<::std::string::String>,
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub nit_interval: ::std::option::Option<i32>,
}
impl DvbNitSettings {
    /// The numeric value placed in the Network Information Table (NIT).
    pub fn network_id(&self) -> ::std::option::Option<i32> {
        self.network_id
    }
    /// The network name text placed in the network_name_descriptor inside the Network Information Table. Maximum length is 256 characters.
    pub fn network_name(&self) -> ::std::option::Option<&str> {
        self.network_name.as_deref()
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn nit_interval(&self) -> ::std::option::Option<i32> {
        self.nit_interval
    }
}
impl DvbNitSettings {
    /// Creates a new builder-style object to manufacture [`DvbNitSettings`](crate::types::DvbNitSettings).
    pub fn builder() -> crate::types::builders::DvbNitSettingsBuilder {
        crate::types::builders::DvbNitSettingsBuilder::default()
    }
}

/// A builder for [`DvbNitSettings`](crate::types::DvbNitSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DvbNitSettingsBuilder {
    pub(crate) network_id: ::std::option::Option<i32>,
    pub(crate) network_name: ::std::option::Option<::std::string::String>,
    pub(crate) nit_interval: ::std::option::Option<i32>,
}
impl DvbNitSettingsBuilder {
    /// The numeric value placed in the Network Information Table (NIT).
    pub fn network_id(mut self, input: i32) -> Self {
        self.network_id = ::std::option::Option::Some(input);
        self
    }
    /// The numeric value placed in the Network Information Table (NIT).
    pub fn set_network_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.network_id = input;
        self
    }
    /// The numeric value placed in the Network Information Table (NIT).
    pub fn get_network_id(&self) -> &::std::option::Option<i32> {
        &self.network_id
    }
    /// The network name text placed in the network_name_descriptor inside the Network Information Table. Maximum length is 256 characters.
    pub fn network_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_name = ::std::option::Option::Some(input.into());
        self
    }
    /// The network name text placed in the network_name_descriptor inside the Network Information Table. Maximum length is 256 characters.
    pub fn set_network_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_name = input;
        self
    }
    /// The network name text placed in the network_name_descriptor inside the Network Information Table. Maximum length is 256 characters.
    pub fn get_network_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_name
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn nit_interval(mut self, input: i32) -> Self {
        self.nit_interval = ::std::option::Option::Some(input);
        self
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn set_nit_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.nit_interval = input;
        self
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn get_nit_interval(&self) -> &::std::option::Option<i32> {
        &self.nit_interval
    }
    /// Consumes the builder and constructs a [`DvbNitSettings`](crate::types::DvbNitSettings).
    pub fn build(self) -> crate::types::DvbNitSettings {
        crate::types::DvbNitSettings {
            network_id: self.network_id,
            network_name: self.network_name,
            nit_interval: self.nit_interval,
        }
    }
}
