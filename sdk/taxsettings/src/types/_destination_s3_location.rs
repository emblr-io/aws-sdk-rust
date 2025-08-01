// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The location of the Amazon S3 bucket that you specify to download your tax documents to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DestinationS3Location {
    /// <p>The name of your Amazon S3 bucket that you specify to download your tax documents to.</p>
    pub bucket: ::std::string::String,
    /// <p>The Amazon S3 object prefix that you specify for your tax document file.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
}
impl DestinationS3Location {
    /// <p>The name of your Amazon S3 bucket that you specify to download your tax documents to.</p>
    pub fn bucket(&self) -> &str {
        use std::ops::Deref;
        self.bucket.deref()
    }
    /// <p>The Amazon S3 object prefix that you specify for your tax document file.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl DestinationS3Location {
    /// Creates a new builder-style object to manufacture [`DestinationS3Location`](crate::types::DestinationS3Location).
    pub fn builder() -> crate::types::builders::DestinationS3LocationBuilder {
        crate::types::builders::DestinationS3LocationBuilder::default()
    }
}

/// A builder for [`DestinationS3Location`](crate::types::DestinationS3Location).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationS3LocationBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
}
impl DestinationS3LocationBuilder {
    /// <p>The name of your Amazon S3 bucket that you specify to download your tax documents to.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your Amazon S3 bucket that you specify to download your tax documents to.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of your Amazon S3 bucket that you specify to download your tax documents to.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The Amazon S3 object prefix that you specify for your tax document file.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 object prefix that you specify for your tax document file.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The Amazon S3 object prefix that you specify for your tax document file.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Consumes the builder and constructs a [`DestinationS3Location`](crate::types::DestinationS3Location).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket`](crate::types::builders::DestinationS3LocationBuilder::bucket)
    pub fn build(self) -> ::std::result::Result<crate::types::DestinationS3Location, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DestinationS3Location {
            bucket: self.bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket",
                    "bucket was not specified but it is required when building DestinationS3Location",
                )
            })?,
            prefix: self.prefix,
        })
    }
}
