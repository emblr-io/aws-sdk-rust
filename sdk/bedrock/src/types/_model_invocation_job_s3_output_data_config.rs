// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the configuration of the S3 location of the output data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelInvocationJobS3OutputDataConfig {
    /// <p>The S3 location of the output data.</p>
    pub s3_uri: ::std::string::String,
    /// <p>The unique identifier of the key that encrypts the S3 location of the output data.</p>
    pub s3_encryption_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account that owns the S3 bucket containing the output data.</p>
    pub s3_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl ModelInvocationJobS3OutputDataConfig {
    /// <p>The S3 location of the output data.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>The unique identifier of the key that encrypts the S3 location of the output data.</p>
    pub fn s3_encryption_key_id(&self) -> ::std::option::Option<&str> {
        self.s3_encryption_key_id.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account that owns the S3 bucket containing the output data.</p>
    pub fn s3_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_owner.as_deref()
    }
}
impl ModelInvocationJobS3OutputDataConfig {
    /// Creates a new builder-style object to manufacture [`ModelInvocationJobS3OutputDataConfig`](crate::types::ModelInvocationJobS3OutputDataConfig).
    pub fn builder() -> crate::types::builders::ModelInvocationJobS3OutputDataConfigBuilder {
        crate::types::builders::ModelInvocationJobS3OutputDataConfigBuilder::default()
    }
}

/// A builder for [`ModelInvocationJobS3OutputDataConfig`](crate::types::ModelInvocationJobS3OutputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelInvocationJobS3OutputDataConfigBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) s3_encryption_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket_owner: ::std::option::Option<::std::string::String>,
}
impl ModelInvocationJobS3OutputDataConfigBuilder {
    /// <p>The S3 location of the output data.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 location of the output data.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The S3 location of the output data.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>The unique identifier of the key that encrypts the S3 location of the output data.</p>
    pub fn s3_encryption_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_encryption_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the key that encrypts the S3 location of the output data.</p>
    pub fn set_s3_encryption_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_encryption_key_id = input;
        self
    }
    /// <p>The unique identifier of the key that encrypts the S3 location of the output data.</p>
    pub fn get_s3_encryption_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_encryption_key_id
    }
    /// <p>The ID of the Amazon Web Services account that owns the S3 bucket containing the output data.</p>
    pub fn s3_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the S3 bucket containing the output data.</p>
    pub fn set_s3_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_owner = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that owns the S3 bucket containing the output data.</p>
    pub fn get_s3_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_owner
    }
    /// Consumes the builder and constructs a [`ModelInvocationJobS3OutputDataConfig`](crate::types::ModelInvocationJobS3OutputDataConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_uri`](crate::types::builders::ModelInvocationJobS3OutputDataConfigBuilder::s3_uri)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ModelInvocationJobS3OutputDataConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ModelInvocationJobS3OutputDataConfig {
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building ModelInvocationJobS3OutputDataConfig",
                )
            })?,
            s3_encryption_key_id: self.s3_encryption_key_id,
            s3_bucket_owner: self.s3_bucket_owner,
        })
    }
}
