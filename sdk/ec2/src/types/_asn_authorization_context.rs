// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides authorization for Amazon to bring an Autonomous System Number (ASN) to a specific Amazon Web Services account using bring your own ASN (BYOASN). For details on the format of the message and signature, see <a href="https://docs.aws.amazon.com/vpc/latest/ipam/tutorials-byoasn.html">Tutorial: Bring your ASN to IPAM</a> in the <i>Amazon VPC IPAM guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AsnAuthorizationContext {
    /// <p>The authorization context's message.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The authorization context's signature.</p>
    pub signature: ::std::option::Option<::std::string::String>,
}
impl AsnAuthorizationContext {
    /// <p>The authorization context's message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>The authorization context's signature.</p>
    pub fn signature(&self) -> ::std::option::Option<&str> {
        self.signature.as_deref()
    }
}
impl AsnAuthorizationContext {
    /// Creates a new builder-style object to manufacture [`AsnAuthorizationContext`](crate::types::AsnAuthorizationContext).
    pub fn builder() -> crate::types::builders::AsnAuthorizationContextBuilder {
        crate::types::builders::AsnAuthorizationContextBuilder::default()
    }
}

/// A builder for [`AsnAuthorizationContext`](crate::types::AsnAuthorizationContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AsnAuthorizationContextBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) signature: ::std::option::Option<::std::string::String>,
}
impl AsnAuthorizationContextBuilder {
    /// <p>The authorization context's message.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authorization context's message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The authorization context's message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The authorization context's signature.</p>
    /// This field is required.
    pub fn signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authorization context's signature.</p>
    pub fn set_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.signature = input;
        self
    }
    /// <p>The authorization context's signature.</p>
    pub fn get_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.signature
    }
    /// Consumes the builder and constructs a [`AsnAuthorizationContext`](crate::types::AsnAuthorizationContext).
    pub fn build(self) -> crate::types::AsnAuthorizationContext {
        crate::types::AsnAuthorizationContext {
            message: self.message,
            signature: self.signature,
        }
    }
}
