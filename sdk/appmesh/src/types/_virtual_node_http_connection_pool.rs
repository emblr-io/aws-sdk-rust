// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a type of connection pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualNodeHttpConnectionPool {
    /// <p>Maximum number of outbound TCP connections Envoy can establish concurrently with all hosts in upstream cluster.</p>
    pub max_connections: i32,
    /// <p>Number of overflowing requests after <code>max_connections</code> Envoy will queue to upstream cluster.</p>
    pub max_pending_requests: ::std::option::Option<i32>,
}
impl VirtualNodeHttpConnectionPool {
    /// <p>Maximum number of outbound TCP connections Envoy can establish concurrently with all hosts in upstream cluster.</p>
    pub fn max_connections(&self) -> i32 {
        self.max_connections
    }
    /// <p>Number of overflowing requests after <code>max_connections</code> Envoy will queue to upstream cluster.</p>
    pub fn max_pending_requests(&self) -> ::std::option::Option<i32> {
        self.max_pending_requests
    }
}
impl VirtualNodeHttpConnectionPool {
    /// Creates a new builder-style object to manufacture [`VirtualNodeHttpConnectionPool`](crate::types::VirtualNodeHttpConnectionPool).
    pub fn builder() -> crate::types::builders::VirtualNodeHttpConnectionPoolBuilder {
        crate::types::builders::VirtualNodeHttpConnectionPoolBuilder::default()
    }
}

/// A builder for [`VirtualNodeHttpConnectionPool`](crate::types::VirtualNodeHttpConnectionPool).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualNodeHttpConnectionPoolBuilder {
    pub(crate) max_connections: ::std::option::Option<i32>,
    pub(crate) max_pending_requests: ::std::option::Option<i32>,
}
impl VirtualNodeHttpConnectionPoolBuilder {
    /// <p>Maximum number of outbound TCP connections Envoy can establish concurrently with all hosts in upstream cluster.</p>
    /// This field is required.
    pub fn max_connections(mut self, input: i32) -> Self {
        self.max_connections = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of outbound TCP connections Envoy can establish concurrently with all hosts in upstream cluster.</p>
    pub fn set_max_connections(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_connections = input;
        self
    }
    /// <p>Maximum number of outbound TCP connections Envoy can establish concurrently with all hosts in upstream cluster.</p>
    pub fn get_max_connections(&self) -> &::std::option::Option<i32> {
        &self.max_connections
    }
    /// <p>Number of overflowing requests after <code>max_connections</code> Envoy will queue to upstream cluster.</p>
    pub fn max_pending_requests(mut self, input: i32) -> Self {
        self.max_pending_requests = ::std::option::Option::Some(input);
        self
    }
    /// <p>Number of overflowing requests after <code>max_connections</code> Envoy will queue to upstream cluster.</p>
    pub fn set_max_pending_requests(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_pending_requests = input;
        self
    }
    /// <p>Number of overflowing requests after <code>max_connections</code> Envoy will queue to upstream cluster.</p>
    pub fn get_max_pending_requests(&self) -> &::std::option::Option<i32> {
        &self.max_pending_requests
    }
    /// Consumes the builder and constructs a [`VirtualNodeHttpConnectionPool`](crate::types::VirtualNodeHttpConnectionPool).
    /// This method will fail if any of the following fields are not set:
    /// - [`max_connections`](crate::types::builders::VirtualNodeHttpConnectionPoolBuilder::max_connections)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualNodeHttpConnectionPool, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualNodeHttpConnectionPool {
            max_connections: self.max_connections.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_connections",
                    "max_connections was not specified but it is required when building VirtualNodeHttpConnectionPool",
                )
            })?,
            max_pending_requests: self.max_pending_requests,
        })
    }
}
