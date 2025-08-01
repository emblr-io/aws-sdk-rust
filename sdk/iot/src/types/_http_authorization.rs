// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The authorization method used to send messages.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HttpAuthorization {
    /// <p>Use Sig V4 authorization. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 Signing Process</a>.</p>
    pub sigv4: ::std::option::Option<crate::types::SigV4Authorization>,
}
impl HttpAuthorization {
    /// <p>Use Sig V4 authorization. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 Signing Process</a>.</p>
    pub fn sigv4(&self) -> ::std::option::Option<&crate::types::SigV4Authorization> {
        self.sigv4.as_ref()
    }
}
impl HttpAuthorization {
    /// Creates a new builder-style object to manufacture [`HttpAuthorization`](crate::types::HttpAuthorization).
    pub fn builder() -> crate::types::builders::HttpAuthorizationBuilder {
        crate::types::builders::HttpAuthorizationBuilder::default()
    }
}

/// A builder for [`HttpAuthorization`](crate::types::HttpAuthorization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HttpAuthorizationBuilder {
    pub(crate) sigv4: ::std::option::Option<crate::types::SigV4Authorization>,
}
impl HttpAuthorizationBuilder {
    /// <p>Use Sig V4 authorization. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 Signing Process</a>.</p>
    pub fn sigv4(mut self, input: crate::types::SigV4Authorization) -> Self {
        self.sigv4 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use Sig V4 authorization. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 Signing Process</a>.</p>
    pub fn set_sigv4(mut self, input: ::std::option::Option<crate::types::SigV4Authorization>) -> Self {
        self.sigv4 = input;
        self
    }
    /// <p>Use Sig V4 authorization. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 Signing Process</a>.</p>
    pub fn get_sigv4(&self) -> &::std::option::Option<crate::types::SigV4Authorization> {
        &self.sigv4
    }
    /// Consumes the builder and constructs a [`HttpAuthorization`](crate::types::HttpAuthorization).
    pub fn build(self) -> crate::types::HttpAuthorization {
        crate::types::HttpAuthorization { sigv4: self.sigv4 }
    }
}
