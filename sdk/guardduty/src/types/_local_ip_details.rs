// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the local IP address of the connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct LocalIpDetails {
    /// <p>The IPv4 local address of the connection.</p>
    pub ip_address_v4: ::std::option::Option<::std::string::String>,
    /// <p>The IPv6 local address of the connection.</p>
    pub ip_address_v6: ::std::option::Option<::std::string::String>,
}
impl LocalIpDetails {
    /// <p>The IPv4 local address of the connection.</p>
    pub fn ip_address_v4(&self) -> ::std::option::Option<&str> {
        self.ip_address_v4.as_deref()
    }
    /// <p>The IPv6 local address of the connection.</p>
    pub fn ip_address_v6(&self) -> ::std::option::Option<&str> {
        self.ip_address_v6.as_deref()
    }
}
impl ::std::fmt::Debug for LocalIpDetails {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("LocalIpDetails");
        formatter.field("ip_address_v4", &"*** Sensitive Data Redacted ***");
        formatter.field("ip_address_v6", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl LocalIpDetails {
    /// Creates a new builder-style object to manufacture [`LocalIpDetails`](crate::types::LocalIpDetails).
    pub fn builder() -> crate::types::builders::LocalIpDetailsBuilder {
        crate::types::builders::LocalIpDetailsBuilder::default()
    }
}

/// A builder for [`LocalIpDetails`](crate::types::LocalIpDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct LocalIpDetailsBuilder {
    pub(crate) ip_address_v4: ::std::option::Option<::std::string::String>,
    pub(crate) ip_address_v6: ::std::option::Option<::std::string::String>,
}
impl LocalIpDetailsBuilder {
    /// <p>The IPv4 local address of the connection.</p>
    pub fn ip_address_v4(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address_v4 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 local address of the connection.</p>
    pub fn set_ip_address_v4(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address_v4 = input;
        self
    }
    /// <p>The IPv4 local address of the connection.</p>
    pub fn get_ip_address_v4(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address_v4
    }
    /// <p>The IPv6 local address of the connection.</p>
    pub fn ip_address_v6(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address_v6 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv6 local address of the connection.</p>
    pub fn set_ip_address_v6(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address_v6 = input;
        self
    }
    /// <p>The IPv6 local address of the connection.</p>
    pub fn get_ip_address_v6(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address_v6
    }
    /// Consumes the builder and constructs a [`LocalIpDetails`](crate::types::LocalIpDetails).
    pub fn build(self) -> crate::types::LocalIpDetails {
        crate::types::LocalIpDetails {
            ip_address_v4: self.ip_address_v4,
            ip_address_v6: self.ip_address_v6,
        }
    }
}
impl ::std::fmt::Debug for LocalIpDetailsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("LocalIpDetailsBuilder");
        formatter.field("ip_address_v4", &"*** Sensitive Data Redacted ***");
        formatter.field("ip_address_v6", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
