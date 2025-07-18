// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutKmsEncryptionKeyInput {
    /// <p>The KMS encryption key ARN.</p>
    /// <p>The KMS key must be single-Region key. Amazon Fraud Detector does not support multi-Region KMS key.</p>
    pub kms_encryption_key_arn: ::std::option::Option<::std::string::String>,
}
impl PutKmsEncryptionKeyInput {
    /// <p>The KMS encryption key ARN.</p>
    /// <p>The KMS key must be single-Region key. Amazon Fraud Detector does not support multi-Region KMS key.</p>
    pub fn kms_encryption_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_encryption_key_arn.as_deref()
    }
}
impl PutKmsEncryptionKeyInput {
    /// Creates a new builder-style object to manufacture [`PutKmsEncryptionKeyInput`](crate::operation::put_kms_encryption_key::PutKmsEncryptionKeyInput).
    pub fn builder() -> crate::operation::put_kms_encryption_key::builders::PutKmsEncryptionKeyInputBuilder {
        crate::operation::put_kms_encryption_key::builders::PutKmsEncryptionKeyInputBuilder::default()
    }
}

/// A builder for [`PutKmsEncryptionKeyInput`](crate::operation::put_kms_encryption_key::PutKmsEncryptionKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutKmsEncryptionKeyInputBuilder {
    pub(crate) kms_encryption_key_arn: ::std::option::Option<::std::string::String>,
}
impl PutKmsEncryptionKeyInputBuilder {
    /// <p>The KMS encryption key ARN.</p>
    /// <p>The KMS key must be single-Region key. Amazon Fraud Detector does not support multi-Region KMS key.</p>
    /// This field is required.
    pub fn kms_encryption_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_encryption_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS encryption key ARN.</p>
    /// <p>The KMS key must be single-Region key. Amazon Fraud Detector does not support multi-Region KMS key.</p>
    pub fn set_kms_encryption_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_encryption_key_arn = input;
        self
    }
    /// <p>The KMS encryption key ARN.</p>
    /// <p>The KMS key must be single-Region key. Amazon Fraud Detector does not support multi-Region KMS key.</p>
    pub fn get_kms_encryption_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_encryption_key_arn
    }
    /// Consumes the builder and constructs a [`PutKmsEncryptionKeyInput`](crate::operation::put_kms_encryption_key::PutKmsEncryptionKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_kms_encryption_key::PutKmsEncryptionKeyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_kms_encryption_key::PutKmsEncryptionKeyInput {
            kms_encryption_key_arn: self.kms_encryption_key_arn,
        })
    }
}
