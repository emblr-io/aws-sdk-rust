// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the Amazon S3 bucket for the disk image.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserBucketDetails {
    /// <p>The Amazon S3 bucket from which the disk image was created.</p>
    pub s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The file name of the disk image.</p>
    pub s3_key: ::std::option::Option<::std::string::String>,
}
impl UserBucketDetails {
    /// <p>The Amazon S3 bucket from which the disk image was created.</p>
    pub fn s3_bucket(&self) -> ::std::option::Option<&str> {
        self.s3_bucket.as_deref()
    }
    /// <p>The file name of the disk image.</p>
    pub fn s3_key(&self) -> ::std::option::Option<&str> {
        self.s3_key.as_deref()
    }
}
impl UserBucketDetails {
    /// Creates a new builder-style object to manufacture [`UserBucketDetails`](crate::types::UserBucketDetails).
    pub fn builder() -> crate::types::builders::UserBucketDetailsBuilder {
        crate::types::builders::UserBucketDetailsBuilder::default()
    }
}

/// A builder for [`UserBucketDetails`](crate::types::UserBucketDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserBucketDetailsBuilder {
    pub(crate) s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key: ::std::option::Option<::std::string::String>,
}
impl UserBucketDetailsBuilder {
    /// <p>The Amazon S3 bucket from which the disk image was created.</p>
    pub fn s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket from which the disk image was created.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>The Amazon S3 bucket from which the disk image was created.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket
    }
    /// <p>The file name of the disk image.</p>
    pub fn s3_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The file name of the disk image.</p>
    pub fn set_s3_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key = input;
        self
    }
    /// <p>The file name of the disk image.</p>
    pub fn get_s3_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key
    }
    /// Consumes the builder and constructs a [`UserBucketDetails`](crate::types::UserBucketDetails).
    pub fn build(self) -> crate::types::UserBucketDetails {
        crate::types::UserBucketDetails {
            s3_bucket: self.s3_bucket,
            s3_key: self.s3_key,
        }
    }
}
