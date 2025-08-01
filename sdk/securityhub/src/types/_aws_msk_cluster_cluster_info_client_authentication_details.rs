// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about different modes of client authentication.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsMskClusterClusterInfoClientAuthenticationDetails {
    /// <p>Provides details for client authentication using SASL.</p>
    pub sasl: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails>,
    /// <p>Provides details for allowing no client authentication.</p>
    pub unauthenticated: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails>,
    /// <p>Provides details for client authentication using TLS.</p>
    pub tls: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails>,
}
impl AwsMskClusterClusterInfoClientAuthenticationDetails {
    /// <p>Provides details for client authentication using SASL.</p>
    pub fn sasl(&self) -> ::std::option::Option<&crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails> {
        self.sasl.as_ref()
    }
    /// <p>Provides details for allowing no client authentication.</p>
    pub fn unauthenticated(&self) -> ::std::option::Option<&crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails> {
        self.unauthenticated.as_ref()
    }
    /// <p>Provides details for client authentication using TLS.</p>
    pub fn tls(&self) -> ::std::option::Option<&crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails> {
        self.tls.as_ref()
    }
}
impl AwsMskClusterClusterInfoClientAuthenticationDetails {
    /// Creates a new builder-style object to manufacture [`AwsMskClusterClusterInfoClientAuthenticationDetails`](crate::types::AwsMskClusterClusterInfoClientAuthenticationDetails).
    pub fn builder() -> crate::types::builders::AwsMskClusterClusterInfoClientAuthenticationDetailsBuilder {
        crate::types::builders::AwsMskClusterClusterInfoClientAuthenticationDetailsBuilder::default()
    }
}

/// A builder for [`AwsMskClusterClusterInfoClientAuthenticationDetails`](crate::types::AwsMskClusterClusterInfoClientAuthenticationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsMskClusterClusterInfoClientAuthenticationDetailsBuilder {
    pub(crate) sasl: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails>,
    pub(crate) unauthenticated: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails>,
    pub(crate) tls: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails>,
}
impl AwsMskClusterClusterInfoClientAuthenticationDetailsBuilder {
    /// <p>Provides details for client authentication using SASL.</p>
    pub fn sasl(mut self, input: crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails) -> Self {
        self.sasl = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details for client authentication using SASL.</p>
    pub fn set_sasl(mut self, input: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails>) -> Self {
        self.sasl = input;
        self
    }
    /// <p>Provides details for client authentication using SASL.</p>
    pub fn get_sasl(&self) -> &::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationSaslDetails> {
        &self.sasl
    }
    /// <p>Provides details for allowing no client authentication.</p>
    pub fn unauthenticated(mut self, input: crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails) -> Self {
        self.unauthenticated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details for allowing no client authentication.</p>
    pub fn set_unauthenticated(
        mut self,
        input: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails>,
    ) -> Self {
        self.unauthenticated = input;
        self
    }
    /// <p>Provides details for allowing no client authentication.</p>
    pub fn get_unauthenticated(&self) -> &::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationUnauthenticatedDetails> {
        &self.unauthenticated
    }
    /// <p>Provides details for client authentication using TLS.</p>
    pub fn tls(mut self, input: crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails) -> Self {
        self.tls = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details for client authentication using TLS.</p>
    pub fn set_tls(mut self, input: ::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails>) -> Self {
        self.tls = input;
        self
    }
    /// <p>Provides details for client authentication using TLS.</p>
    pub fn get_tls(&self) -> &::std::option::Option<crate::types::AwsMskClusterClusterInfoClientAuthenticationTlsDetails> {
        &self.tls
    }
    /// Consumes the builder and constructs a [`AwsMskClusterClusterInfoClientAuthenticationDetails`](crate::types::AwsMskClusterClusterInfoClientAuthenticationDetails).
    pub fn build(self) -> crate::types::AwsMskClusterClusterInfoClientAuthenticationDetails {
        crate::types::AwsMskClusterClusterInfoClientAuthenticationDetails {
            sasl: self.sasl,
            unauthenticated: self.unauthenticated,
            tls: self.tls,
        }
    }
}
