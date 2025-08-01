// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the virtual gateway's listener's Secret Discovery Service certificate.The proxy must be configured with a local SDS provider via a Unix Domain Socket. See App Mesh<a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/tls.html">TLS documentation</a> for more info.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualGatewayListenerTlsSdsCertificate {
    /// <p>A reference to an object that represents the name of the secret secret requested from the Secret Discovery Service provider representing Transport Layer Security (TLS) materials like a certificate or certificate chain.</p>
    pub secret_name: ::std::string::String,
}
impl VirtualGatewayListenerTlsSdsCertificate {
    /// <p>A reference to an object that represents the name of the secret secret requested from the Secret Discovery Service provider representing Transport Layer Security (TLS) materials like a certificate or certificate chain.</p>
    pub fn secret_name(&self) -> &str {
        use std::ops::Deref;
        self.secret_name.deref()
    }
}
impl VirtualGatewayListenerTlsSdsCertificate {
    /// Creates a new builder-style object to manufacture [`VirtualGatewayListenerTlsSdsCertificate`](crate::types::VirtualGatewayListenerTlsSdsCertificate).
    pub fn builder() -> crate::types::builders::VirtualGatewayListenerTlsSdsCertificateBuilder {
        crate::types::builders::VirtualGatewayListenerTlsSdsCertificateBuilder::default()
    }
}

/// A builder for [`VirtualGatewayListenerTlsSdsCertificate`](crate::types::VirtualGatewayListenerTlsSdsCertificate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualGatewayListenerTlsSdsCertificateBuilder {
    pub(crate) secret_name: ::std::option::Option<::std::string::String>,
}
impl VirtualGatewayListenerTlsSdsCertificateBuilder {
    /// <p>A reference to an object that represents the name of the secret secret requested from the Secret Discovery Service provider representing Transport Layer Security (TLS) materials like a certificate or certificate chain.</p>
    /// This field is required.
    pub fn secret_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A reference to an object that represents the name of the secret secret requested from the Secret Discovery Service provider representing Transport Layer Security (TLS) materials like a certificate or certificate chain.</p>
    pub fn set_secret_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_name = input;
        self
    }
    /// <p>A reference to an object that represents the name of the secret secret requested from the Secret Discovery Service provider representing Transport Layer Security (TLS) materials like a certificate or certificate chain.</p>
    pub fn get_secret_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_name
    }
    /// Consumes the builder and constructs a [`VirtualGatewayListenerTlsSdsCertificate`](crate::types::VirtualGatewayListenerTlsSdsCertificate).
    /// This method will fail if any of the following fields are not set:
    /// - [`secret_name`](crate::types::builders::VirtualGatewayListenerTlsSdsCertificateBuilder::secret_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::VirtualGatewayListenerTlsSdsCertificate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualGatewayListenerTlsSdsCertificate {
            secret_name: self.secret_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "secret_name",
                    "secret_name was not specified but it is required when building VirtualGatewayListenerTlsSdsCertificate",
                )
            })?,
        })
    }
}
