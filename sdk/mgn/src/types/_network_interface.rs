// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Network interface.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkInterface {
    /// <p>Network interface Mac address.</p>
    pub mac_address: ::std::option::Option<::std::string::String>,
    /// <p>Network interface IPs.</p>
    pub ips: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Network interface primary IP.</p>
    pub is_primary: ::std::option::Option<bool>,
}
impl NetworkInterface {
    /// <p>Network interface Mac address.</p>
    pub fn mac_address(&self) -> ::std::option::Option<&str> {
        self.mac_address.as_deref()
    }
    /// <p>Network interface IPs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ips.is_none()`.
    pub fn ips(&self) -> &[::std::string::String] {
        self.ips.as_deref().unwrap_or_default()
    }
    /// <p>Network interface primary IP.</p>
    pub fn is_primary(&self) -> ::std::option::Option<bool> {
        self.is_primary
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
    pub(crate) mac_address: ::std::option::Option<::std::string::String>,
    pub(crate) ips: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) is_primary: ::std::option::Option<bool>,
}
impl NetworkInterfaceBuilder {
    /// <p>Network interface Mac address.</p>
    pub fn mac_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mac_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Network interface Mac address.</p>
    pub fn set_mac_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mac_address = input;
        self
    }
    /// <p>Network interface Mac address.</p>
    pub fn get_mac_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.mac_address
    }
    /// Appends an item to `ips`.
    ///
    /// To override the contents of this collection use [`set_ips`](Self::set_ips).
    ///
    /// <p>Network interface IPs.</p>
    pub fn ips(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ips.unwrap_or_default();
        v.push(input.into());
        self.ips = ::std::option::Option::Some(v);
        self
    }
    /// <p>Network interface IPs.</p>
    pub fn set_ips(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ips = input;
        self
    }
    /// <p>Network interface IPs.</p>
    pub fn get_ips(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ips
    }
    /// <p>Network interface primary IP.</p>
    pub fn is_primary(mut self, input: bool) -> Self {
        self.is_primary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Network interface primary IP.</p>
    pub fn set_is_primary(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_primary = input;
        self
    }
    /// <p>Network interface primary IP.</p>
    pub fn get_is_primary(&self) -> &::std::option::Option<bool> {
        &self.is_primary
    }
    /// Consumes the builder and constructs a [`NetworkInterface`](crate::types::NetworkInterface).
    pub fn build(self) -> crate::types::NetworkInterface {
        crate::types::NetworkInterface {
            mac_address: self.mac_address,
            ips: self.ips,
            is_primary: self.is_primary,
        }
    }
}
