// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>In a <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html">CreateResolverEndpoint</a> request, the IP address that DNS queries originate from (for outbound endpoints) or that you forward DNS queries to (for inbound endpoints). <code>IpAddressRequest</code> also includes the ID of the subnet that contains the IP address.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IpAddressRequest {
    /// <p>The ID of the subnet that contains the IP address.</p>
    pub subnet_id: ::std::string::String,
    /// <p>The IPv4 address that you want to use for DNS queries.</p>
    pub ip: ::std::option::Option<::std::string::String>,
    /// <p>The IPv6 address that you want to use for DNS queries.</p>
    pub ipv6: ::std::option::Option<::std::string::String>,
}
impl IpAddressRequest {
    /// <p>The ID of the subnet that contains the IP address.</p>
    pub fn subnet_id(&self) -> &str {
        use std::ops::Deref;
        self.subnet_id.deref()
    }
    /// <p>The IPv4 address that you want to use for DNS queries.</p>
    pub fn ip(&self) -> ::std::option::Option<&str> {
        self.ip.as_deref()
    }
    /// <p>The IPv6 address that you want to use for DNS queries.</p>
    pub fn ipv6(&self) -> ::std::option::Option<&str> {
        self.ipv6.as_deref()
    }
}
impl IpAddressRequest {
    /// Creates a new builder-style object to manufacture [`IpAddressRequest`](crate::types::IpAddressRequest).
    pub fn builder() -> crate::types::builders::IpAddressRequestBuilder {
        crate::types::builders::IpAddressRequestBuilder::default()
    }
}

/// A builder for [`IpAddressRequest`](crate::types::IpAddressRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IpAddressRequestBuilder {
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) ip: ::std::option::Option<::std::string::String>,
    pub(crate) ipv6: ::std::option::Option<::std::string::String>,
}
impl IpAddressRequestBuilder {
    /// <p>The ID of the subnet that contains the IP address.</p>
    /// This field is required.
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet that contains the IP address.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The ID of the subnet that contains the IP address.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// <p>The IPv4 address that you want to use for DNS queries.</p>
    pub fn ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 address that you want to use for DNS queries.</p>
    pub fn set_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip = input;
        self
    }
    /// <p>The IPv4 address that you want to use for DNS queries.</p>
    pub fn get_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip
    }
    /// <p>The IPv6 address that you want to use for DNS queries.</p>
    pub fn ipv6(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ipv6 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv6 address that you want to use for DNS queries.</p>
    pub fn set_ipv6(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ipv6 = input;
        self
    }
    /// <p>The IPv6 address that you want to use for DNS queries.</p>
    pub fn get_ipv6(&self) -> &::std::option::Option<::std::string::String> {
        &self.ipv6
    }
    /// Consumes the builder and constructs a [`IpAddressRequest`](crate::types::IpAddressRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`subnet_id`](crate::types::builders::IpAddressRequestBuilder::subnet_id)
    pub fn build(self) -> ::std::result::Result<crate::types::IpAddressRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IpAddressRequest {
            subnet_id: self.subnet_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subnet_id",
                    "subnet_id was not specified but it is required when building IpAddressRequest",
                )
            })?,
            ip: self.ip,
            ipv6: self.ipv6,
        })
    }
}
