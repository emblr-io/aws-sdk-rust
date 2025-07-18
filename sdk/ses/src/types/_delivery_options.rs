// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeliveryOptions {
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS). If the value is <code>Require</code>, messages are only delivered if a TLS connection can be established. If the value is <code>Optional</code>, messages can be delivered in plain text if a TLS connection can't be established.</p>
    pub tls_policy: ::std::option::Option<crate::types::TlsPolicy>,
}
impl DeliveryOptions {
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS). If the value is <code>Require</code>, messages are only delivered if a TLS connection can be established. If the value is <code>Optional</code>, messages can be delivered in plain text if a TLS connection can't be established.</p>
    pub fn tls_policy(&self) -> ::std::option::Option<&crate::types::TlsPolicy> {
        self.tls_policy.as_ref()
    }
}
impl DeliveryOptions {
    /// Creates a new builder-style object to manufacture [`DeliveryOptions`](crate::types::DeliveryOptions).
    pub fn builder() -> crate::types::builders::DeliveryOptionsBuilder {
        crate::types::builders::DeliveryOptionsBuilder::default()
    }
}

/// A builder for [`DeliveryOptions`](crate::types::DeliveryOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeliveryOptionsBuilder {
    pub(crate) tls_policy: ::std::option::Option<crate::types::TlsPolicy>,
}
impl DeliveryOptionsBuilder {
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS). If the value is <code>Require</code>, messages are only delivered if a TLS connection can be established. If the value is <code>Optional</code>, messages can be delivered in plain text if a TLS connection can't be established.</p>
    pub fn tls_policy(mut self, input: crate::types::TlsPolicy) -> Self {
        self.tls_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS). If the value is <code>Require</code>, messages are only delivered if a TLS connection can be established. If the value is <code>Optional</code>, messages can be delivered in plain text if a TLS connection can't be established.</p>
    pub fn set_tls_policy(mut self, input: ::std::option::Option<crate::types::TlsPolicy>) -> Self {
        self.tls_policy = input;
        self
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS). If the value is <code>Require</code>, messages are only delivered if a TLS connection can be established. If the value is <code>Optional</code>, messages can be delivered in plain text if a TLS connection can't be established.</p>
    pub fn get_tls_policy(&self) -> &::std::option::Option<crate::types::TlsPolicy> {
        &self.tls_policy
    }
    /// Consumes the builder and constructs a [`DeliveryOptions`](crate::types::DeliveryOptions).
    pub fn build(self) -> crate::types::DeliveryOptions {
        crate::types::DeliveryOptions { tls_policy: self.tls_policy }
    }
}
