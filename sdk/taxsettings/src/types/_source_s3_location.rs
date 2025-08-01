// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon S3 bucket in your account where your tax document is located.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceS3Location {
    /// <p>The name of your Amazon S3 bucket that your tax document is located.</p>
    pub bucket: ::std::string::String,
    /// <p>The object key of your tax document object in Amazon S3.</p>
    pub key: ::std::string::String,
}
impl SourceS3Location {
    /// <p>The name of your Amazon S3 bucket that your tax document is located.</p>
    pub fn bucket(&self) -> &str {
        use std::ops::Deref;
        self.bucket.deref()
    }
    /// <p>The object key of your tax document object in Amazon S3.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
}
impl SourceS3Location {
    /// Creates a new builder-style object to manufacture [`SourceS3Location`](crate::types::SourceS3Location).
    pub fn builder() -> crate::types::builders::SourceS3LocationBuilder {
        crate::types::builders::SourceS3LocationBuilder::default()
    }
}

/// A builder for [`SourceS3Location`](crate::types::SourceS3Location).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceS3LocationBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl SourceS3LocationBuilder {
    /// <p>The name of your Amazon S3 bucket that your tax document is located.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your Amazon S3 bucket that your tax document is located.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of your Amazon S3 bucket that your tax document is located.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The object key of your tax document object in Amazon S3.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The object key of your tax document object in Amazon S3.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The object key of your tax document object in Amazon S3.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`SourceS3Location`](crate::types::SourceS3Location).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket`](crate::types::builders::SourceS3LocationBuilder::bucket)
    /// - [`key`](crate::types::builders::SourceS3LocationBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::SourceS3Location, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SourceS3Location {
            bucket: self.bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket",
                    "bucket was not specified but it is required when building SourceS3Location",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building SourceS3Location",
                )
            })?,
        })
    }
}
