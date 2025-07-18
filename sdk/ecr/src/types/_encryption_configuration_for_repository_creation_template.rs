// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The encryption configuration to associate with the repository creation template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EncryptionConfigurationForRepositoryCreationTemplate {
    /// <p>The encryption type to use.</p>
    /// <p>If you use the <code>KMS</code> encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html">Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// <p>If you use the <code>AES256</code> encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES256 encryption algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html">Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    pub encryption_type: crate::types::EncryptionType,
    /// <p>If you use the <code>KMS</code> encryption type, specify the KMS key to use for encryption. The full ARN of the KMS key must be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used.</p>
    pub kms_key: ::std::option::Option<::std::string::String>,
}
impl EncryptionConfigurationForRepositoryCreationTemplate {
    /// <p>The encryption type to use.</p>
    /// <p>If you use the <code>KMS</code> encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html">Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// <p>If you use the <code>AES256</code> encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES256 encryption algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html">Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    pub fn encryption_type(&self) -> &crate::types::EncryptionType {
        &self.encryption_type
    }
    /// <p>If you use the <code>KMS</code> encryption type, specify the KMS key to use for encryption. The full ARN of the KMS key must be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used.</p>
    pub fn kms_key(&self) -> ::std::option::Option<&str> {
        self.kms_key.as_deref()
    }
}
impl EncryptionConfigurationForRepositoryCreationTemplate {
    /// Creates a new builder-style object to manufacture [`EncryptionConfigurationForRepositoryCreationTemplate`](crate::types::EncryptionConfigurationForRepositoryCreationTemplate).
    pub fn builder() -> crate::types::builders::EncryptionConfigurationForRepositoryCreationTemplateBuilder {
        crate::types::builders::EncryptionConfigurationForRepositoryCreationTemplateBuilder::default()
    }
}

/// A builder for [`EncryptionConfigurationForRepositoryCreationTemplate`](crate::types::EncryptionConfigurationForRepositoryCreationTemplate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EncryptionConfigurationForRepositoryCreationTemplateBuilder {
    pub(crate) encryption_type: ::std::option::Option<crate::types::EncryptionType>,
    pub(crate) kms_key: ::std::option::Option<::std::string::String>,
}
impl EncryptionConfigurationForRepositoryCreationTemplateBuilder {
    /// <p>The encryption type to use.</p>
    /// <p>If you use the <code>KMS</code> encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html">Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// <p>If you use the <code>AES256</code> encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES256 encryption algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html">Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// This field is required.
    pub fn encryption_type(mut self, input: crate::types::EncryptionType) -> Self {
        self.encryption_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption type to use.</p>
    /// <p>If you use the <code>KMS</code> encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html">Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// <p>If you use the <code>AES256</code> encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES256 encryption algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html">Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    pub fn set_encryption_type(mut self, input: ::std::option::Option<crate::types::EncryptionType>) -> Self {
        self.encryption_type = input;
        self
    }
    /// <p>The encryption type to use.</p>
    /// <p>If you use the <code>KMS</code> encryption type, the contents of the repository will be encrypted using server-side encryption with Key Management Service key stored in KMS. When you use KMS to encrypt your data, you can either use the default Amazon Web Services managed KMS key for Amazon ECR, or specify your own KMS key, which you already created. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html">Protecting data using server-side encryption with an KMS key stored in Key Management Service (SSE-KMS)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    /// <p>If you use the <code>AES256</code> encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES256 encryption algorithm. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html">Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3)</a> in the <i>Amazon Simple Storage Service Console Developer Guide</i>.</p>
    pub fn get_encryption_type(&self) -> &::std::option::Option<crate::types::EncryptionType> {
        &self.encryption_type
    }
    /// <p>If you use the <code>KMS</code> encryption type, specify the KMS key to use for encryption. The full ARN of the KMS key must be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used.</p>
    pub fn kms_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you use the <code>KMS</code> encryption type, specify the KMS key to use for encryption. The full ARN of the KMS key must be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used.</p>
    pub fn set_kms_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key = input;
        self
    }
    /// <p>If you use the <code>KMS</code> encryption type, specify the KMS key to use for encryption. The full ARN of the KMS key must be specified. The key must exist in the same Region as the repository. If no key is specified, the default Amazon Web Services managed KMS key for Amazon ECR will be used.</p>
    pub fn get_kms_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key
    }
    /// Consumes the builder and constructs a [`EncryptionConfigurationForRepositoryCreationTemplate`](crate::types::EncryptionConfigurationForRepositoryCreationTemplate).
    /// This method will fail if any of the following fields are not set:
    /// - [`encryption_type`](crate::types::builders::EncryptionConfigurationForRepositoryCreationTemplateBuilder::encryption_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::EncryptionConfigurationForRepositoryCreationTemplate, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::EncryptionConfigurationForRepositoryCreationTemplate {
            encryption_type: self.encryption_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "encryption_type",
                    "encryption_type was not specified but it is required when building EncryptionConfigurationForRepositoryCreationTemplate",
                )
            })?,
            kms_key: self.kms_key,
        })
    }
}
