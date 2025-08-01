// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a network interface.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkInterface {
    /// <p>The ID of the subnet.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the network interface.</p>
    pub network_interface_id: ::std::option::Option<::std::string::String>,
}
impl NetworkInterface {
    /// <p>The ID of the subnet.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
    /// <p>The ID of the network interface.</p>
    pub fn network_interface_id(&self) -> ::std::option::Option<&str> {
        self.network_interface_id.as_deref()
    }
}
impl NetworkInterface {
    /// Creates a new builder-style object to manufacture [`NetworkInterface`](crate::types::NetworkInterface).
    pub fn builder() -> crate::types::builders::NetworkInterfaceBuilder {
        crate::types::builders::NetworkInterfaceBuilder::default()
    }
}

/// A builder for [`NetworkInterface`](crate::types::NetworkInterface).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkInterfaceBuilder {
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) network_interface_id: ::std::option::Option<::std::string::String>,
}
impl NetworkInterfaceBuilder {
    /// <p>The ID of the subnet.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The ID of the subnet.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// <p>The ID of the network interface.</p>
    pub fn network_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn set_network_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_interface_id = input;
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn get_network_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_interface_id
    }
    /// Consumes the builder and constructs a [`NetworkInterface`](crate::types::NetworkInterface).
    pub fn build(self) -> crate::types::NetworkInterface {
        crate::types::NetworkInterface {
            subnet_id: self.subnet_id,
            network_interface_id: self.network_interface_id,
        }
    }
}
