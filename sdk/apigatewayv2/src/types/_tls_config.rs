// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The TLS configuration for a private integration. If you specify a TLS configuration, private integration traffic uses the HTTPS protocol. Supported only for HTTP APIs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TlsConfig {
    /// <p>If you specify a server name, API Gateway uses it to verify the hostname on the integration's certificate. The server name is also included in the TLS handshake to support Server Name Indication (SNI) or virtual hosting.</p>
    pub server_name_to_verify: ::std::option::Option<::std::string::String>,
}
impl TlsConfig {
    /// <p>If you specify a server name, API Gateway uses it to verify the hostname on the integration's certificate. The server name is also included in the TLS handshake to support Server Name Indication (SNI) or virtual hosting.</p>
    pub fn server_name_to_verify(&self) -> ::std::option::Option<&str> {
        self.server_name_to_verify.as_deref()
    }
}
impl TlsConfig {
    /// Creates a new builder-style object to manufacture [`TlsConfig`](crate::types::TlsConfig).
    pub fn builder() -> crate::types::builders::TlsConfigBuilder {
        crate::types::builders::TlsConfigBuilder::default()
    }
}

/// A builder for [`TlsConfig`](crate::types::TlsConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TlsConfigBuilder {
    pub(crate) server_name_to_verify: ::std::option::Option<::std::string::String>,
}
impl TlsConfigBuilder {
    /// <p>If you specify a server name, API Gateway uses it to verify the hostname on the integration's certificate. The server name is also included in the TLS handshake to support Server Name Indication (SNI) or virtual hosting.</p>
    pub fn server_name_to_verify(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_name_to_verify = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you specify a server name, API Gateway uses it to verify the hostname on the integration's certificate. The server name is also included in the TLS handshake to support Server Name Indication (SNI) or virtual hosting.</p>
    pub fn set_server_name_to_verify(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_name_to_verify = input;
        self
    }
    /// <p>If you specify a server name, API Gateway uses it to verify the hostname on the integration's certificate. The server name is also included in the TLS handshake to support Server Name Indication (SNI) or virtual hosting.</p>
    pub fn get_server_name_to_verify(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_name_to_verify
    }
    /// Consumes the builder and constructs a [`TlsConfig`](crate::types::TlsConfig).
    pub fn build(self) -> crate::types::TlsConfig {
        crate::types::TlsConfig {
            server_name_to_verify: self.server_name_to_verify,
        }
    }
}
