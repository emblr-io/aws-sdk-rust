// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Asynchronous invocation output data settings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AsyncInvokeS3OutputDataConfig {
    /// <p>An object URI starting with <code>s3://</code>.</p>
    pub s3_uri: ::std::string::String,
    /// <p>A KMS encryption key ID.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>If the bucket belongs to another AWS account, specify that account's ID.</p>
    pub bucket_owner: ::std::option::Option<::std::string::String>,
}
impl AsyncInvokeS3OutputDataConfig {
    /// <p>An object URI starting with <code>s3://</code>.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>A KMS encryption key ID.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>If the bucket belongs to another AWS account, specify that account's ID.</p>
    pub fn bucket_owner(&self) -> ::std::option::Option<&str> {
        self.bucket_owner.as_deref()
    }
}
impl AsyncInvokeS3OutputDataConfig {
    /// Creates a new builder-style object to manufacture [`AsyncInvokeS3OutputDataConfig`](crate::types::AsyncInvokeS3OutputDataConfig).
    pub fn builder() -> crate::types::builders::AsyncInvokeS3OutputDataConfigBuilder {
        crate::types::builders::AsyncInvokeS3OutputDataConfigBuilder::default()
    }
}

/// A builder for [`AsyncInvokeS3OutputDataConfig`](crate::types::AsyncInvokeS3OutputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AsyncInvokeS3OutputDataConfigBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_owner: ::std::option::Option<::std::string::String>,
}
impl AsyncInvokeS3OutputDataConfigBuilder {
    /// <p>An object URI starting with <code>s3://</code>.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An object URI starting with <code>s3://</code>.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>An object URI starting with <code>s3://</code>.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>A KMS encryption key ID.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A KMS encryption key ID.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>A KMS encryption key ID.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>If the bucket belongs to another AWS account, specify that account's ID.</p>
    pub fn bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the bucket belongs to another AWS account, specify that account's ID.</p>
    pub fn set_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_owner = input;
        self
    }
    /// <p>If the bucket belongs to another AWS account, specify that account's ID.</p>
    pub fn get_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_owner
    }
    /// Consumes the builder and constructs a [`AsyncInvokeS3OutputDataConfig`](crate::types::AsyncInvokeS3OutputDataConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_uri`](crate::types::builders::AsyncInvokeS3OutputDataConfigBuilder::s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::AsyncInvokeS3OutputDataConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AsyncInvokeS3OutputDataConfig {
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building AsyncInvokeS3OutputDataConfig",
                )
            })?,
            kms_key_id: self.kms_key_id,
            bucket_owner: self.bucket_owner,
        })
    }
}
