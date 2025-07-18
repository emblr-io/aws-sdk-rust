// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a listener's Transport Layer Security (TLS) validation context.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListenerTlsValidationContext {
    /// <p>A reference to where to retrieve the trust chain when validating a peer’s Transport Layer Security (TLS) certificate.</p>
    pub trust: ::std::option::Option<crate::types::ListenerTlsValidationContextTrust>,
    /// <p>A reference to an object that represents the SANs for a listener's Transport Layer Security (TLS) validation context.</p>
    pub subject_alternative_names: ::std::option::Option<crate::types::SubjectAlternativeNames>,
}
impl ListenerTlsValidationContext {
    /// <p>A reference to where to retrieve the trust chain when validating a peer’s Transport Layer Security (TLS) certificate.</p>
    pub fn trust(&self) -> ::std::option::Option<&crate::types::ListenerTlsValidationContextTrust> {
        self.trust.as_ref()
    }
    /// <p>A reference to an object that represents the SANs for a listener's Transport Layer Security (TLS) validation context.</p>
    pub fn subject_alternative_names(&self) -> ::std::option::Option<&crate::types::SubjectAlternativeNames> {
        self.subject_alternative_names.as_ref()
    }
}
impl ListenerTlsValidationContext {
    /// Creates a new builder-style object to manufacture [`ListenerTlsValidationContext`](crate::types::ListenerTlsValidationContext).
    pub fn builder() -> crate::types::builders::ListenerTlsValidationContextBuilder {
        crate::types::builders::ListenerTlsValidationContextBuilder::default()
    }
}

/// A builder for [`ListenerTlsValidationContext`](crate::types::ListenerTlsValidationContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListenerTlsValidationContextBuilder {
    pub(crate) trust: ::std::option::Option<crate::types::ListenerTlsValidationContextTrust>,
    pub(crate) subject_alternative_names: ::std::option::Option<crate::types::SubjectAlternativeNames>,
}
impl ListenerTlsValidationContextBuilder {
    /// <p>A reference to where to retrieve the trust chain when validating a peer’s Transport Layer Security (TLS) certificate.</p>
    /// This field is required.
    pub fn trust(mut self, input: crate::types::ListenerTlsValidationContextTrust) -> Self {
        self.trust = ::std::option::Option::Some(input);
        self
    }
    /// <p>A reference to where to retrieve the trust chain when validating a peer’s Transport Layer Security (TLS) certificate.</p>
    pub fn set_trust(mut self, input: ::std::option::Option<crate::types::ListenerTlsValidationContextTrust>) -> Self {
        self.trust = input;
        self
    }
    /// <p>A reference to where to retrieve the trust chain when validating a peer’s Transport Layer Security (TLS) certificate.</p>
    pub fn get_trust(&self) -> &::std::option::Option<crate::types::ListenerTlsValidationContextTrust> {
        &self.trust
    }
    /// <p>A reference to an object that represents the SANs for a listener's Transport Layer Security (TLS) validation context.</p>
    pub fn subject_alternative_names(mut self, input: crate::types::SubjectAlternativeNames) -> Self {
        self.subject_alternative_names = ::std::option::Option::Some(input);
        self
    }
    /// <p>A reference to an object that represents the SANs for a listener's Transport Layer Security (TLS) validation context.</p>
    pub fn set_subject_alternative_names(mut self, input: ::std::option::Option<crate::types::SubjectAlternativeNames>) -> Self {
        self.subject_alternative_names = input;
        self
    }
    /// <p>A reference to an object that represents the SANs for a listener's Transport Layer Security (TLS) validation context.</p>
    pub fn get_subject_alternative_names(&self) -> &::std::option::Option<crate::types::SubjectAlternativeNames> {
        &self.subject_alternative_names
    }
    /// Consumes the builder and constructs a [`ListenerTlsValidationContext`](crate::types::ListenerTlsValidationContext).
    pub fn build(self) -> crate::types::ListenerTlsValidationContext {
        crate::types::ListenerTlsValidationContext {
            trust: self.trust,
            subject_alternative_names: self.subject_alternative_names,
        }
    }
}
