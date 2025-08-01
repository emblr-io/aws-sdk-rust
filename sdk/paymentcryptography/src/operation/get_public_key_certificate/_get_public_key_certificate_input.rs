// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPublicKeyCertificateInput {
    /// <p>The <code>KeyARN</code> of the asymmetric key pair.</p>
    pub key_identifier: ::std::option::Option<::std::string::String>,
}
impl GetPublicKeyCertificateInput {
    /// <p>The <code>KeyARN</code> of the asymmetric key pair.</p>
    pub fn key_identifier(&self) -> ::std::option::Option<&str> {
        self.key_identifier.as_deref()
    }
}
impl GetPublicKeyCertificateInput {
    /// Creates a new builder-style object to manufacture [`GetPublicKeyCertificateInput`](crate::operation::get_public_key_certificate::GetPublicKeyCertificateInput).
    pub fn builder() -> crate::operation::get_public_key_certificate::builders::GetPublicKeyCertificateInputBuilder {
        crate::operation::get_public_key_certificate::builders::GetPublicKeyCertificateInputBuilder::default()
    }
}

/// A builder for [`GetPublicKeyCertificateInput`](crate::operation::get_public_key_certificate::GetPublicKeyCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPublicKeyCertificateInputBuilder {
    pub(crate) key_identifier: ::std::option::Option<::std::string::String>,
}
impl GetPublicKeyCertificateInputBuilder {
    /// <p>The <code>KeyARN</code> of the asymmetric key pair.</p>
    /// This field is required.
    pub fn key_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>KeyARN</code> of the asymmetric key pair.</p>
    pub fn set_key_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_identifier = input;
        self
    }
    /// <p>The <code>KeyARN</code> of the asymmetric key pair.</p>
    pub fn get_key_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_identifier
    }
    /// Consumes the builder and constructs a [`GetPublicKeyCertificateInput`](crate::operation::get_public_key_certificate::GetPublicKeyCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_public_key_certificate::GetPublicKeyCertificateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_public_key_certificate::GetPublicKeyCertificateInput {
            key_identifier: self.key_identifier,
        })
    }
}
