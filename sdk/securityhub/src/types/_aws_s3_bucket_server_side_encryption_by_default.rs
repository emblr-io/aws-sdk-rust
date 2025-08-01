// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the default server-side encryption to apply to new objects in the bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3BucketServerSideEncryptionByDefault {
    /// <p>Server-side encryption algorithm to use for the default encryption. Valid values are <code>aws: kms</code> or <code>AES256</code>.</p>
    pub sse_algorithm: ::std::option::Option<::std::string::String>,
    /// <p>KMS key ID to use for the default encryption.</p>
    pub kms_master_key_id: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketServerSideEncryptionByDefault {
    /// <p>Server-side encryption algorithm to use for the default encryption. Valid values are <code>aws: kms</code> or <code>AES256</code>.</p>
    pub fn sse_algorithm(&self) -> ::std::option::Option<&str> {
        self.sse_algorithm.as_deref()
    }
    /// <p>KMS key ID to use for the default encryption.</p>
    pub fn kms_master_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_master_key_id.as_deref()
    }
}
impl AwsS3BucketServerSideEncryptionByDefault {
    /// Creates a new builder-style object to manufacture [`AwsS3BucketServerSideEncryptionByDefault`](crate::types::AwsS3BucketServerSideEncryptionByDefault).
    pub fn builder() -> crate::types::builders::AwsS3BucketServerSideEncryptionByDefaultBuilder {
        crate::types::builders::AwsS3BucketServerSideEncryptionByDefaultBuilder::default()
    }
}

/// A builder for [`AwsS3BucketServerSideEncryptionByDefault`](crate::types::AwsS3BucketServerSideEncryptionByDefault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3BucketServerSideEncryptionByDefaultBuilder {
    pub(crate) sse_algorithm: ::std::option::Option<::std::string::String>,
    pub(crate) kms_master_key_id: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketServerSideEncryptionByDefaultBuilder {
    /// <p>Server-side encryption algorithm to use for the default encryption. Valid values are <code>aws: kms</code> or <code>AES256</code>.</p>
    pub fn sse_algorithm(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sse_algorithm = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Server-side encryption algorithm to use for the default encryption. Valid values are <code>aws: kms</code> or <code>AES256</code>.</p>
    pub fn set_sse_algorithm(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sse_algorithm = input;
        self
    }
    /// <p>Server-side encryption algorithm to use for the default encryption. Valid values are <code>aws: kms</code> or <code>AES256</code>.</p>
    pub fn get_sse_algorithm(&self) -> &::std::option::Option<::std::string::String> {
        &self.sse_algorithm
    }
    /// <p>KMS key ID to use for the default encryption.</p>
    pub fn kms_master_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_master_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>KMS key ID to use for the default encryption.</p>
    pub fn set_kms_master_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_master_key_id = input;
        self
    }
    /// <p>KMS key ID to use for the default encryption.</p>
    pub fn get_kms_master_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_master_key_id
    }
    /// Consumes the builder and constructs a [`AwsS3BucketServerSideEncryptionByDefault`](crate::types::AwsS3BucketServerSideEncryptionByDefault).
    pub fn build(self) -> crate::types::AwsS3BucketServerSideEncryptionByDefault {
        crate::types::AwsS3BucketServerSideEncryptionByDefault {
            sse_algorithm: self.sse_algorithm,
            kms_master_key_id: self.kms_master_key_id,
        }
    }
}
