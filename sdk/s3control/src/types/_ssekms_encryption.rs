// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration for the use of SSE-KMS to encrypt generated manifest objects.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SsekmsEncryption {
    /// <p>Specifies the ID of the Amazon Web Services Key Management Service (Amazon Web Services KMS) symmetric encryption customer managed key to use for encrypting generated manifest objects.</p>
    pub key_id: ::std::string::String,
}
impl SsekmsEncryption {
    /// <p>Specifies the ID of the Amazon Web Services Key Management Service (Amazon Web Services KMS) symmetric encryption customer managed key to use for encrypting generated manifest objects.</p>
    pub fn key_id(&self) -> &str {
        use std::ops::Deref;
        self.key_id.deref()
    }
}
impl SsekmsEncryption {
    /// Creates a new builder-style object to manufacture [`SsekmsEncryption`](crate::types::SsekmsEncryption).
    pub fn builder() -> crate::types::builders::SsekmsEncryptionBuilder {
        crate::types::builders::SsekmsEncryptionBuilder::default()
    }
}

/// A builder for [`SsekmsEncryption`](crate::types::SsekmsEncryption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SsekmsEncryptionBuilder {
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
}
impl SsekmsEncryptionBuilder {
    /// <p>Specifies the ID of the Amazon Web Services Key Management Service (Amazon Web Services KMS) symmetric encryption customer managed key to use for encrypting generated manifest objects.</p>
    /// This field is required.
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the Amazon Web Services Key Management Service (Amazon Web Services KMS) symmetric encryption customer managed key to use for encrypting generated manifest objects.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>Specifies the ID of the Amazon Web Services Key Management Service (Amazon Web Services KMS) symmetric encryption customer managed key to use for encrypting generated manifest objects.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// Consumes the builder and constructs a [`SsekmsEncryption`](crate::types::SsekmsEncryption).
    /// This method will fail if any of the following fields are not set:
    /// - [`key_id`](crate::types::builders::SsekmsEncryptionBuilder::key_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SsekmsEncryption, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SsekmsEncryption {
            key_id: self.key_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key_id",
                    "key_id was not specified but it is required when building SsekmsEncryption",
                )
            })?,
        })
    }
}
