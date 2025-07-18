// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Used in CreateNetworkRequest.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IpPoolCreateRequest {
    /// A CIDR block of IP addresses to reserve for MediaLive Anywhere.
    pub cidr: ::std::option::Option<::std::string::String>,
}
impl IpPoolCreateRequest {
    /// A CIDR block of IP addresses to reserve for MediaLive Anywhere.
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
}
impl IpPoolCreateRequest {
    /// Creates a new builder-style object to manufacture [`IpPoolCreateRequest`](crate::types::IpPoolCreateRequest).
    pub fn builder() -> crate::types::builders::IpPoolCreateRequestBuilder {
        crate::types::builders::IpPoolCreateRequestBuilder::default()
    }
}

/// A builder for [`IpPoolCreateRequest`](crate::types::IpPoolCreateRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IpPoolCreateRequestBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
}
impl IpPoolCreateRequestBuilder {
    /// A CIDR block of IP addresses to reserve for MediaLive Anywhere.
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// A CIDR block of IP addresses to reserve for MediaLive Anywhere.
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// A CIDR block of IP addresses to reserve for MediaLive Anywhere.
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// Consumes the builder and constructs a [`IpPoolCreateRequest`](crate::types::IpPoolCreateRequest).
    pub fn build(self) -> crate::types::IpPoolCreateRequest {
        crate::types::IpPoolCreateRequest { cidr: self.cidr }
    }
}
