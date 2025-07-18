// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a type of connection pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualNodeHttp2ConnectionPool {
    /// <p>Maximum number of inflight requests Envoy can concurrently support across hosts in upstream cluster.</p>
    pub max_requests: i32,
}
impl VirtualNodeHttp2ConnectionPool {
    /// <p>Maximum number of inflight requests Envoy can concurrently support across hosts in upstream cluster.</p>
    pub fn max_requests(&self) -> i32 {
        self.max_requests
    }
}
impl VirtualNodeHttp2ConnectionPool {
    /// Creates a new builder-style object to manufacture [`VirtualNodeHttp2ConnectionPool`](crate::types::VirtualNodeHttp2ConnectionPool).
    pub fn builder() -> crate::types::builders::VirtualNodeHttp2ConnectionPoolBuilder {
        crate::types::builders::VirtualNodeHttp2ConnectionPoolBuilder::default()
    }
}

/// A builder for [`VirtualNodeHttp2ConnectionPool`](crate::types::VirtualNodeHttp2ConnectionPool).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualNodeHttp2ConnectionPoolBuilder {
    pub(crate) max_requests: ::std::option::Option<i32>,
}
impl VirtualNodeHttp2ConnectionPoolBuilder {
    /// <p>Maximum number of inflight requests Envoy can concurrently support across hosts in upstream cluster.</p>
    /// This field is required.
    pub fn max_requests(mut self, input: i32) -> Self {
        self.max_requests = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of inflight requests Envoy can concurrently support across hosts in upstream cluster.</p>
    pub fn set_max_requests(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_requests = input;
        self
    }
    /// <p>Maximum number of inflight requests Envoy can concurrently support across hosts in upstream cluster.</p>
    pub fn get_max_requests(&self) -> &::std::option::Option<i32> {
        &self.max_requests
    }
    /// Consumes the builder and constructs a [`VirtualNodeHttp2ConnectionPool`](crate::types::VirtualNodeHttp2ConnectionPool).
    /// This method will fail if any of the following fields are not set:
    /// - [`max_requests`](crate::types::builders::VirtualNodeHttp2ConnectionPoolBuilder::max_requests)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualNodeHttp2ConnectionPool, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualNodeHttp2ConnectionPool {
            max_requests: self.max_requests.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_requests",
                    "max_requests was not specified but it is required when building VirtualNodeHttp2ConnectionPool",
                )
            })?,
        })
    }
}
