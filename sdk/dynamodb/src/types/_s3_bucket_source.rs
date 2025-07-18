// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The S3 bucket that is being imported from.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3BucketSource {
    /// <p>The account number of the S3 bucket that is being imported from. If the bucket is owned by the requester this is optional.</p>
    pub s3_bucket_owner: ::std::option::Option<::std::string::String>,
    /// <p>The S3 bucket that is being imported from.</p>
    pub s3_bucket: ::std::string::String,
    /// <p>The key prefix shared by all S3 Objects that are being imported.</p>
    pub s3_key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3BucketSource {
    /// <p>The account number of the S3 bucket that is being imported from. If the bucket is owned by the requester this is optional.</p>
    pub fn s3_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_owner.as_deref()
    }
    /// <p>The S3 bucket that is being imported from.</p>
    pub fn s3_bucket(&self) -> &str {
        use std::ops::Deref;
        self.s3_bucket.deref()
    }
    /// <p>The key prefix shared by all S3 Objects that are being imported.</p>
    pub fn s3_key_prefix(&self) -> ::std::option::Option<&str> {
        self.s3_key_prefix.as_deref()
    }
}
impl S3BucketSource {
    /// Creates a new builder-style object to manufacture [`S3BucketSource`](crate::types::S3BucketSource).
    pub fn builder() -> crate::types::builders::S3BucketSourceBuilder {
        crate::types::builders::S3BucketSourceBuilder::default()
    }
}

/// A builder for [`S3BucketSource`](crate::types::S3BucketSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3BucketSourceBuilder {
    pub(crate) s3_bucket_owner: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3BucketSourceBuilder {
    /// <p>The account number of the S3 bucket that is being imported from. If the bucket is owned by the requester this is optional.</p>
    pub fn s3_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account number of the S3 bucket that is being imported from. If the bucket is owned by the requester this is optional.</p>
    pub fn set_s3_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_owner = input;
        self
    }
    /// <p>The account number of the S3 bucket that is being imported from. If the bucket is owned by the requester this is optional.</p>
    pub fn get_s3_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_owner
    }
    /// <p>The S3 bucket that is being imported from.</p>
    /// This field is required.
    pub fn s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 bucket that is being imported from.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>The S3 bucket that is being imported from.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket
    }
    /// <p>The key prefix shared by all S3 Objects that are being imported.</p>
    pub fn s3_key_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key prefix shared by all S3 Objects that are being imported.</p>
    pub fn set_s3_key_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key_prefix = input;
        self
    }
    /// <p>The key prefix shared by all S3 Objects that are being imported.</p>
    pub fn get_s3_key_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key_prefix
    }
    /// Consumes the builder and constructs a [`S3BucketSource`](crate::types::S3BucketSource).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_bucket`](crate::types::builders::S3BucketSourceBuilder::s3_bucket)
    pub fn build(self) -> ::std::result::Result<crate::types::S3BucketSource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3BucketSource {
            s3_bucket_owner: self.s3_bucket_owner,
            s3_bucket: self.s3_bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_bucket",
                    "s3_bucket was not specified but it is required when building S3BucketSource",
                )
            })?,
            s3_key_prefix: self.s3_key_prefix,
        })
    }
}
