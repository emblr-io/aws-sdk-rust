// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the information required for client programs to connect to the endpoint for a DAX cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Endpoint {
    /// <p>The DNS hostname of the endpoint.</p>
    pub address: ::std::option::Option<::std::string::String>,
    /// <p>The port number that applications should use to connect to the endpoint.</p>
    pub port: i32,
    /// <p>The URL that applications should use to connect to the endpoint. The default ports are 8111 for the "dax" protocol and 9111 for the "daxs" protocol.</p>
    pub url: ::std::option::Option<::std::string::String>,
}
impl Endpoint {
    /// <p>The DNS hostname of the endpoint.</p>
    pub fn address(&self) -> ::std::option::Option<&str> {
        self.address.as_deref()
    }
    /// <p>The port number that applications should use to connect to the endpoint.</p>
    pub fn port(&self) -> i32 {
        self.port
    }
    /// <p>The URL that applications should use to connect to the endpoint. The default ports are 8111 for the "dax" protocol and 9111 for the "daxs" protocol.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl Endpoint {
    /// Creates a new builder-style object to manufacture [`Endpoint`](crate::types::Endpoint).
    pub fn builder() -> crate::types::builders::EndpointBuilder {
        crate::types::builders::EndpointBuilder::default()
    }
}

/// A builder for [`Endpoint`](crate::types::Endpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointBuilder {
    pub(crate) address: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl EndpointBuilder {
    /// <p>The DNS hostname of the endpoint.</p>
    pub fn address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DNS hostname of the endpoint.</p>
    pub fn set_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address = input;
        self
    }
    /// <p>The DNS hostname of the endpoint.</p>
    pub fn get_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.address
    }
    /// <p>The port number that applications should use to connect to the endpoint.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number that applications should use to connect to the endpoint.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port number that applications should use to connect to the endpoint.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>The URL that applications should use to connect to the endpoint. The default ports are 8111 for the "dax" protocol and 9111 for the "daxs" protocol.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL that applications should use to connect to the endpoint. The default ports are 8111 for the "dax" protocol and 9111 for the "daxs" protocol.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL that applications should use to connect to the endpoint. The default ports are 8111 for the "dax" protocol and 9111 for the "daxs" protocol.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`Endpoint`](crate::types::Endpoint).
    pub fn build(self) -> crate::types::Endpoint {
        crate::types::Endpoint {
            address: self.address,
            port: self.port.unwrap_or_default(),
            url: self.url,
        }
    }
}
