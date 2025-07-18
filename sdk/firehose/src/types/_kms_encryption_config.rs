// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an encryption key for a destination in Amazon S3.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KmsEncryptionConfig {
    /// <p>The Amazon Resource Name (ARN) of the encryption key. Must belong to the same Amazon Web Services Region as the destination Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a>.</p>
    pub awskms_key_arn: ::std::string::String,
}
impl KmsEncryptionConfig {
    /// <p>The Amazon Resource Name (ARN) of the encryption key. Must belong to the same Amazon Web Services Region as the destination Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a>.</p>
    pub fn awskms_key_arn(&self) -> &str {
        use std::ops::Deref;
        self.awskms_key_arn.deref()
    }
}
impl KmsEncryptionConfig {
    /// Creates a new builder-style object to manufacture [`KmsEncryptionConfig`](crate::types::KmsEncryptionConfig).
    pub fn builder() -> crate::types::builders::KmsEncryptionConfigBuilder {
        crate::types::builders::KmsEncryptionConfigBuilder::default()
    }
}

/// A builder for [`KmsEncryptionConfig`](crate::types::KmsEncryptionConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KmsEncryptionConfigBuilder {
    pub(crate) awskms_key_arn: ::std::option::Option<::std::string::String>,
}
impl KmsEncryptionConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) of the encryption key. Must belong to the same Amazon Web Services Region as the destination Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a>.</p>
    /// This field is required.
    pub fn awskms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.awskms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the encryption key. Must belong to the same Amazon Web Services Region as the destination Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a>.</p>
    pub fn set_awskms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.awskms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the encryption key. Must belong to the same Amazon Web Services Region as the destination Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a>.</p>
    pub fn get_awskms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.awskms_key_arn
    }
    /// Consumes the builder and constructs a [`KmsEncryptionConfig`](crate::types::KmsEncryptionConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`awskms_key_arn`](crate::types::builders::KmsEncryptionConfigBuilder::awskms_key_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::KmsEncryptionConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::KmsEncryptionConfig {
            awskms_key_arn: self.awskms_key_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "awskms_key_arn",
                    "awskms_key_arn was not specified but it is required when building KmsEncryptionConfig",
                )
            })?,
        })
    }
}
