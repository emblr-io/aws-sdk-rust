// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Pair of multicast url and source ip address (optional) that make up a multicast source.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MulticastSourceUpdateRequest {
    /// This represents the ip address of the device sending the multicast stream.
    pub source_ip: ::std::option::Option<::std::string::String>,
    /// This represents the customer's source URL where multicast stream is pulled from.
    pub url: ::std::option::Option<::std::string::String>,
}
impl MulticastSourceUpdateRequest {
    /// This represents the ip address of the device sending the multicast stream.
    pub fn source_ip(&self) -> ::std::option::Option<&str> {
        self.source_ip.as_deref()
    }
    /// This represents the customer's source URL where multicast stream is pulled from.
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl MulticastSourceUpdateRequest {
    /// Creates a new builder-style object to manufacture [`MulticastSourceUpdateRequest`](crate::types::MulticastSourceUpdateRequest).
    pub fn builder() -> crate::types::builders::MulticastSourceUpdateRequestBuilder {
        crate::types::builders::MulticastSourceUpdateRequestBuilder::default()
    }
}

/// A builder for [`MulticastSourceUpdateRequest`](crate::types::MulticastSourceUpdateRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MulticastSourceUpdateRequestBuilder {
    pub(crate) source_ip: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl MulticastSourceUpdateRequestBuilder {
    /// This represents the ip address of the device sending the multicast stream.
    pub fn source_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// This represents the ip address of the device sending the multicast stream.
    pub fn set_source_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_ip = input;
        self
    }
    /// This represents the ip address of the device sending the multicast stream.
    pub fn get_source_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_ip
    }
    /// This represents the customer's source URL where multicast stream is pulled from.
    /// This field is required.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// This represents the customer's source URL where multicast stream is pulled from.
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// This represents the customer's source URL where multicast stream is pulled from.
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`MulticastSourceUpdateRequest`](crate::types::MulticastSourceUpdateRequest).
    pub fn build(self) -> crate::types::MulticastSourceUpdateRequest {
        crate::types::MulticastSourceUpdateRequest {
            source_ip: self.source_ip,
            url: self.url,
        }
    }
}
