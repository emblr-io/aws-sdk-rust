// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that describes a trusted token issuer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrustedTokenIssuerMetadata {
    /// <p>The ARN of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub trusted_token_issuer_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of trusted token issuer.</p>
    pub trusted_token_issuer_type: ::std::option::Option<crate::types::TrustedTokenIssuerType>,
}
impl TrustedTokenIssuerMetadata {
    /// <p>The ARN of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn trusted_token_issuer_arn(&self) -> ::std::option::Option<&str> {
        self.trusted_token_issuer_arn.as_deref()
    }
    /// <p>The name of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of trusted token issuer.</p>
    pub fn trusted_token_issuer_type(&self) -> ::std::option::Option<&crate::types::TrustedTokenIssuerType> {
        self.trusted_token_issuer_type.as_ref()
    }
}
impl TrustedTokenIssuerMetadata {
    /// Creates a new builder-style object to manufacture [`TrustedTokenIssuerMetadata`](crate::types::TrustedTokenIssuerMetadata).
    pub fn builder() -> crate::types::builders::TrustedTokenIssuerMetadataBuilder {
        crate::types::builders::TrustedTokenIssuerMetadataBuilder::default()
    }
}

/// A builder for [`TrustedTokenIssuerMetadata`](crate::types::TrustedTokenIssuerMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrustedTokenIssuerMetadataBuilder {
    pub(crate) trusted_token_issuer_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) trusted_token_issuer_type: ::std::option::Option<crate::types::TrustedTokenIssuerType>,
}
impl TrustedTokenIssuerMetadataBuilder {
    /// <p>The ARN of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn trusted_token_issuer_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trusted_token_issuer_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn set_trusted_token_issuer_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trusted_token_issuer_arn = input;
        self
    }
    /// <p>The ARN of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn get_trusted_token_issuer_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.trusted_token_issuer_arn
    }
    /// <p>The name of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the trusted token issuer configuration in the instance of IAM Identity Center.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of trusted token issuer.</p>
    pub fn trusted_token_issuer_type(mut self, input: crate::types::TrustedTokenIssuerType) -> Self {
        self.trusted_token_issuer_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of trusted token issuer.</p>
    pub fn set_trusted_token_issuer_type(mut self, input: ::std::option::Option<crate::types::TrustedTokenIssuerType>) -> Self {
        self.trusted_token_issuer_type = input;
        self
    }
    /// <p>The type of trusted token issuer.</p>
    pub fn get_trusted_token_issuer_type(&self) -> &::std::option::Option<crate::types::TrustedTokenIssuerType> {
        &self.trusted_token_issuer_type
    }
    /// Consumes the builder and constructs a [`TrustedTokenIssuerMetadata`](crate::types::TrustedTokenIssuerMetadata).
    pub fn build(self) -> crate::types::TrustedTokenIssuerMetadata {
        crate::types::TrustedTokenIssuerMetadata {
            trusted_token_issuer_arn: self.trusted_token_issuer_arn,
            name: self.name,
            trusted_token_issuer_type: self.trusted_token_issuer_type,
        }
    }
}
