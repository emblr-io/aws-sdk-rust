// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Amazon CloudFront supports gRPC, an open-source remote procedure call (RPC) framework built on HTTP/2. gRPC offers bi-directional streaming and binary protocol that buffers payloads, making it suitable for applications that require low latency communications.</p>
/// <p>To enable your distribution to handle gRPC requests, you must include HTTP/2 as one of the supported <code>HTTP</code> versions and allow <code>HTTP</code> methods, including <code>POST</code>.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-using-grpc.html">Using gRPC with CloudFront distributions</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GrpcConfig {
    /// <p>Enables your CloudFront distribution to receive gRPC requests and to proxy them directly to your origins.</p>
    pub enabled: bool,
}
impl GrpcConfig {
    /// <p>Enables your CloudFront distribution to receive gRPC requests and to proxy them directly to your origins.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
impl GrpcConfig {
    /// Creates a new builder-style object to manufacture [`GrpcConfig`](crate::types::GrpcConfig).
    pub fn builder() -> crate::types::builders::GrpcConfigBuilder {
        crate::types::builders::GrpcConfigBuilder::default()
    }
}

/// A builder for [`GrpcConfig`](crate::types::GrpcConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GrpcConfigBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl GrpcConfigBuilder {
    /// <p>Enables your CloudFront distribution to receive gRPC requests and to proxy them directly to your origins.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables your CloudFront distribution to receive gRPC requests and to proxy them directly to your origins.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Enables your CloudFront distribution to receive gRPC requests and to proxy them directly to your origins.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`GrpcConfig`](crate::types::GrpcConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`enabled`](crate::types::builders::GrpcConfigBuilder::enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::GrpcConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GrpcConfig {
            enabled: self.enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enabled",
                    "enabled was not specified but it is required when building GrpcConfig",
                )
            })?,
        })
    }
}
