// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configurations related to in-transit encryption for the security configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InTransitEncryptionConfiguration {
    /// <p>TLS certificate-related configuration input for the security configuration.</p>
    pub tls_certificate_configuration: ::std::option::Option<crate::types::TlsCertificateConfiguration>,
}
impl InTransitEncryptionConfiguration {
    /// <p>TLS certificate-related configuration input for the security configuration.</p>
    pub fn tls_certificate_configuration(&self) -> ::std::option::Option<&crate::types::TlsCertificateConfiguration> {
        self.tls_certificate_configuration.as_ref()
    }
}
impl InTransitEncryptionConfiguration {
    /// Creates a new builder-style object to manufacture [`InTransitEncryptionConfiguration`](crate::types::InTransitEncryptionConfiguration).
    pub fn builder() -> crate::types::builders::InTransitEncryptionConfigurationBuilder {
        crate::types::builders::InTransitEncryptionConfigurationBuilder::default()
    }
}

/// A builder for [`InTransitEncryptionConfiguration`](crate::types::InTransitEncryptionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InTransitEncryptionConfigurationBuilder {
    pub(crate) tls_certificate_configuration: ::std::option::Option<crate::types::TlsCertificateConfiguration>,
}
impl InTransitEncryptionConfigurationBuilder {
    /// <p>TLS certificate-related configuration input for the security configuration.</p>
    pub fn tls_certificate_configuration(mut self, input: crate::types::TlsCertificateConfiguration) -> Self {
        self.tls_certificate_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>TLS certificate-related configuration input for the security configuration.</p>
    pub fn set_tls_certificate_configuration(mut self, input: ::std::option::Option<crate::types::TlsCertificateConfiguration>) -> Self {
        self.tls_certificate_configuration = input;
        self
    }
    /// <p>TLS certificate-related configuration input for the security configuration.</p>
    pub fn get_tls_certificate_configuration(&self) -> &::std::option::Option<crate::types::TlsCertificateConfiguration> {
        &self.tls_certificate_configuration
    }
    /// Consumes the builder and constructs a [`InTransitEncryptionConfiguration`](crate::types::InTransitEncryptionConfiguration).
    pub fn build(self) -> crate::types::InTransitEncryptionConfiguration {
        crate::types::InTransitEncryptionConfiguration {
            tls_certificate_configuration: self.tls_certificate_configuration,
        }
    }
}
