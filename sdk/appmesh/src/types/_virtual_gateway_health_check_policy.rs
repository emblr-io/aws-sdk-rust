// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the health check policy for a virtual gateway's listener.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualGatewayHealthCheckPolicy {
    /// <p>The amount of time to wait when receiving a response from the health check, in milliseconds.</p>
    pub timeout_millis: i64,
    /// <p>The time period in milliseconds between each health check execution.</p>
    pub interval_millis: i64,
    /// <p>The protocol for the health check request. If you specify <code>grpc</code>, then your service must conform to the <a href="https://github.com/grpc/grpc/blob/master/doc/health-checking.md">GRPC Health Checking Protocol</a>.</p>
    pub protocol: crate::types::VirtualGatewayPortProtocol,
    /// <p>The destination port for the health check request. This port must match the port defined in the <code>PortMapping</code> for the listener.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>The destination path for the health check request. This value is only used if the specified protocol is HTTP or HTTP/2. For any other protocol, this value is ignored.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>The number of consecutive successful health checks that must occur before declaring the listener healthy.</p>
    pub healthy_threshold: i32,
    /// <p>The number of consecutive failed health checks that must occur before declaring a virtual gateway unhealthy.</p>
    pub unhealthy_threshold: i32,
}
impl VirtualGatewayHealthCheckPolicy {
    /// <p>The amount of time to wait when receiving a response from the health check, in milliseconds.</p>
    pub fn timeout_millis(&self) -> i64 {
        self.timeout_millis
    }
    /// <p>The time period in milliseconds between each health check execution.</p>
    pub fn interval_millis(&self) -> i64 {
        self.interval_millis
    }
    /// <p>The protocol for the health check request. If you specify <code>grpc</code>, then your service must conform to the <a href="https://github.com/grpc/grpc/blob/master/doc/health-checking.md">GRPC Health Checking Protocol</a>.</p>
    pub fn protocol(&self) -> &crate::types::VirtualGatewayPortProtocol {
        &self.protocol
    }
    /// <p>The destination port for the health check request. This port must match the port defined in the <code>PortMapping</code> for the listener.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>The destination path for the health check request. This value is only used if the specified protocol is HTTP or HTTP/2. For any other protocol, this value is ignored.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>The number of consecutive successful health checks that must occur before declaring the listener healthy.</p>
    pub fn healthy_threshold(&self) -> i32 {
        self.healthy_threshold
    }
    /// <p>The number of consecutive failed health checks that must occur before declaring a virtual gateway unhealthy.</p>
    pub fn unhealthy_threshold(&self) -> i32 {
        self.unhealthy_threshold
    }
}
impl VirtualGatewayHealthCheckPolicy {
    /// Creates a new builder-style object to manufacture [`VirtualGatewayHealthCheckPolicy`](crate::types::VirtualGatewayHealthCheckPolicy).
    pub fn builder() -> crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder {
        crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::default()
    }
}

/// A builder for [`VirtualGatewayHealthCheckPolicy`](crate::types::VirtualGatewayHealthCheckPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualGatewayHealthCheckPolicyBuilder {
    pub(crate) timeout_millis: ::std::option::Option<i64>,
    pub(crate) interval_millis: ::std::option::Option<i64>,
    pub(crate) protocol: ::std::option::Option<crate::types::VirtualGatewayPortProtocol>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) healthy_threshold: ::std::option::Option<i32>,
    pub(crate) unhealthy_threshold: ::std::option::Option<i32>,
}
impl VirtualGatewayHealthCheckPolicyBuilder {
    /// <p>The amount of time to wait when receiving a response from the health check, in milliseconds.</p>
    /// This field is required.
    pub fn timeout_millis(mut self, input: i64) -> Self {
        self.timeout_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time to wait when receiving a response from the health check, in milliseconds.</p>
    pub fn set_timeout_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.timeout_millis = input;
        self
    }
    /// <p>The amount of time to wait when receiving a response from the health check, in milliseconds.</p>
    pub fn get_timeout_millis(&self) -> &::std::option::Option<i64> {
        &self.timeout_millis
    }
    /// <p>The time period in milliseconds between each health check execution.</p>
    /// This field is required.
    pub fn interval_millis(mut self, input: i64) -> Self {
        self.interval_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time period in milliseconds between each health check execution.</p>
    pub fn set_interval_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.interval_millis = input;
        self
    }
    /// <p>The time period in milliseconds between each health check execution.</p>
    pub fn get_interval_millis(&self) -> &::std::option::Option<i64> {
        &self.interval_millis
    }
    /// <p>The protocol for the health check request. If you specify <code>grpc</code>, then your service must conform to the <a href="https://github.com/grpc/grpc/blob/master/doc/health-checking.md">GRPC Health Checking Protocol</a>.</p>
    /// This field is required.
    pub fn protocol(mut self, input: crate::types::VirtualGatewayPortProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protocol for the health check request. If you specify <code>grpc</code>, then your service must conform to the <a href="https://github.com/grpc/grpc/blob/master/doc/health-checking.md">GRPC Health Checking Protocol</a>.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::VirtualGatewayPortProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol for the health check request. If you specify <code>grpc</code>, then your service must conform to the <a href="https://github.com/grpc/grpc/blob/master/doc/health-checking.md">GRPC Health Checking Protocol</a>.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::VirtualGatewayPortProtocol> {
        &self.protocol
    }
    /// <p>The destination port for the health check request. This port must match the port defined in the <code>PortMapping</code> for the listener.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination port for the health check request. This port must match the port defined in the <code>PortMapping</code> for the listener.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>The destination port for the health check request. This port must match the port defined in the <code>PortMapping</code> for the listener.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>The destination path for the health check request. This value is only used if the specified protocol is HTTP or HTTP/2. For any other protocol, this value is ignored.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The destination path for the health check request. This value is only used if the specified protocol is HTTP or HTTP/2. For any other protocol, this value is ignored.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The destination path for the health check request. This value is only used if the specified protocol is HTTP or HTTP/2. For any other protocol, this value is ignored.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>The number of consecutive successful health checks that must occur before declaring the listener healthy.</p>
    /// This field is required.
    pub fn healthy_threshold(mut self, input: i32) -> Self {
        self.healthy_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of consecutive successful health checks that must occur before declaring the listener healthy.</p>
    pub fn set_healthy_threshold(mut self, input: ::std::option::Option<i32>) -> Self {
        self.healthy_threshold = input;
        self
    }
    /// <p>The number of consecutive successful health checks that must occur before declaring the listener healthy.</p>
    pub fn get_healthy_threshold(&self) -> &::std::option::Option<i32> {
        &self.healthy_threshold
    }
    /// <p>The number of consecutive failed health checks that must occur before declaring a virtual gateway unhealthy.</p>
    /// This field is required.
    pub fn unhealthy_threshold(mut self, input: i32) -> Self {
        self.unhealthy_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of consecutive failed health checks that must occur before declaring a virtual gateway unhealthy.</p>
    pub fn set_unhealthy_threshold(mut self, input: ::std::option::Option<i32>) -> Self {
        self.unhealthy_threshold = input;
        self
    }
    /// <p>The number of consecutive failed health checks that must occur before declaring a virtual gateway unhealthy.</p>
    pub fn get_unhealthy_threshold(&self) -> &::std::option::Option<i32> {
        &self.unhealthy_threshold
    }
    /// Consumes the builder and constructs a [`VirtualGatewayHealthCheckPolicy`](crate::types::VirtualGatewayHealthCheckPolicy).
    /// This method will fail if any of the following fields are not set:
    /// - [`timeout_millis`](crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::timeout_millis)
    /// - [`interval_millis`](crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::interval_millis)
    /// - [`protocol`](crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::protocol)
    /// - [`healthy_threshold`](crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::healthy_threshold)
    /// - [`unhealthy_threshold`](crate::types::builders::VirtualGatewayHealthCheckPolicyBuilder::unhealthy_threshold)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualGatewayHealthCheckPolicy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualGatewayHealthCheckPolicy {
            timeout_millis: self.timeout_millis.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timeout_millis",
                    "timeout_millis was not specified but it is required when building VirtualGatewayHealthCheckPolicy",
                )
            })?,
            interval_millis: self.interval_millis.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "interval_millis",
                    "interval_millis was not specified but it is required when building VirtualGatewayHealthCheckPolicy",
                )
            })?,
            protocol: self.protocol.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "protocol",
                    "protocol was not specified but it is required when building VirtualGatewayHealthCheckPolicy",
                )
            })?,
            port: self.port,
            path: self.path,
            healthy_threshold: self.healthy_threshold.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "healthy_threshold",
                    "healthy_threshold was not specified but it is required when building VirtualGatewayHealthCheckPolicy",
                )
            })?,
            unhealthy_threshold: self.unhealthy_threshold.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unhealthy_threshold",
                    "unhealthy_threshold was not specified but it is required when building VirtualGatewayHealthCheckPolicy",
                )
            })?,
        })
    }
}
