// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The endpoint from which data should be migrated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomerNodeEndpoint {
    /// <p>The address of the node endpoint</p>
    pub address: ::std::option::Option<::std::string::String>,
    /// <p>The port of the node endpoint</p>
    pub port: ::std::option::Option<i32>,
}
impl CustomerNodeEndpoint {
    /// <p>The address of the node endpoint</p>
    pub fn address(&self) -> ::std::option::Option<&str> {
        self.address.as_deref()
    }
    /// <p>The port of the node endpoint</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
}
impl CustomerNodeEndpoint {
    /// Creates a new builder-style object to manufacture [`CustomerNodeEndpoint`](crate::types::CustomerNodeEndpoint).
    pub fn builder() -> crate::types::builders::CustomerNodeEndpointBuilder {
        crate::types::builders::CustomerNodeEndpointBuilder::default()
    }
}

/// A builder for [`CustomerNodeEndpoint`](crate::types::CustomerNodeEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomerNodeEndpointBuilder {
    pub(crate) address: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
}
impl CustomerNodeEndpointBuilder {
    /// <p>The address of the node endpoint</p>
    pub fn address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address of the node endpoint</p>
    pub fn set_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address = input;
        self
    }
    /// <p>The address of the node endpoint</p>
    pub fn get_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.address
    }
    /// <p>The port of the node endpoint</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port of the node endpoint</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The port of the node endpoint</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// Consumes the builder and constructs a [`CustomerNodeEndpoint`](crate::types::CustomerNodeEndpoint).
    pub fn build(self) -> crate::types::CustomerNodeEndpoint {
        crate::types::CustomerNodeEndpoint {
            address: self.address,
            port: self.port,
        }
    }
}
