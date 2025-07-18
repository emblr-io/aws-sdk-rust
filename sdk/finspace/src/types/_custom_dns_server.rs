// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomDnsServer {
    /// <p>The name of the DNS server.</p>
    pub custom_dns_server_name: ::std::string::String,
    /// <p>The IP address of the DNS server.</p>
    pub custom_dns_server_ip: ::std::string::String,
}
impl CustomDnsServer {
    /// <p>The name of the DNS server.</p>
    pub fn custom_dns_server_name(&self) -> &str {
        use std::ops::Deref;
        self.custom_dns_server_name.deref()
    }
    /// <p>The IP address of the DNS server.</p>
    pub fn custom_dns_server_ip(&self) -> &str {
        use std::ops::Deref;
        self.custom_dns_server_ip.deref()
    }
}
impl CustomDnsServer {
    /// Creates a new builder-style object to manufacture [`CustomDnsServer`](crate::types::CustomDnsServer).
    pub fn builder() -> crate::types::builders::CustomDnsServerBuilder {
        crate::types::builders::CustomDnsServerBuilder::default()
    }
}

/// A builder for [`CustomDnsServer`](crate::types::CustomDnsServer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomDnsServerBuilder {
    pub(crate) custom_dns_server_name: ::std::option::Option<::std::string::String>,
    pub(crate) custom_dns_server_ip: ::std::option::Option<::std::string::String>,
}
impl CustomDnsServerBuilder {
    /// <p>The name of the DNS server.</p>
    /// This field is required.
    pub fn custom_dns_server_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_dns_server_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DNS server.</p>
    pub fn set_custom_dns_server_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_dns_server_name = input;
        self
    }
    /// <p>The name of the DNS server.</p>
    pub fn get_custom_dns_server_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_dns_server_name
    }
    /// <p>The IP address of the DNS server.</p>
    /// This field is required.
    pub fn custom_dns_server_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_dns_server_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address of the DNS server.</p>
    pub fn set_custom_dns_server_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_dns_server_ip = input;
        self
    }
    /// <p>The IP address of the DNS server.</p>
    pub fn get_custom_dns_server_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_dns_server_ip
    }
    /// Consumes the builder and constructs a [`CustomDnsServer`](crate::types::CustomDnsServer).
    /// This method will fail if any of the following fields are not set:
    /// - [`custom_dns_server_name`](crate::types::builders::CustomDnsServerBuilder::custom_dns_server_name)
    /// - [`custom_dns_server_ip`](crate::types::builders::CustomDnsServerBuilder::custom_dns_server_ip)
    pub fn build(self) -> ::std::result::Result<crate::types::CustomDnsServer, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CustomDnsServer {
            custom_dns_server_name: self.custom_dns_server_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_dns_server_name",
                    "custom_dns_server_name was not specified but it is required when building CustomDnsServer",
                )
            })?,
            custom_dns_server_ip: self.custom_dns_server_ip.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_dns_server_ip",
                    "custom_dns_server_ip was not specified but it is required when building CustomDnsServer",
                )
            })?,
        })
    }
}
