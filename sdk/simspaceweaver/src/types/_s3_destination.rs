// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Amazon S3 bucket and optional folder (object key prefix) where SimSpace Weaver creates a file.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Destination {
    /// <p>The name of an Amazon S3 bucket. For more information about buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-buckets-s3.html">Creating, configuring, and working with Amazon S3 buckets</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub bucket_name: ::std::string::String,
    /// <p>A string prefix for an Amazon S3 object key. It's usually a folder name. For more information about folders in Amazon S3, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html">Organizing objects in the Amazon S3 console using folders</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub object_key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3Destination {
    /// <p>The name of an Amazon S3 bucket. For more information about buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-buckets-s3.html">Creating, configuring, and working with Amazon S3 buckets</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn bucket_name(&self) -> &str {
        use std::ops::Deref;
        self.bucket_name.deref()
    }
    /// <p>A string prefix for an Amazon S3 object key. It's usually a folder name. For more information about folders in Amazon S3, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html">Organizing objects in the Amazon S3 console using folders</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn object_key_prefix(&self) -> ::std::option::Option<&str> {
        self.object_key_prefix.as_deref()
    }
}
impl S3Destination {
    /// Creates a new builder-style object to manufacture [`S3Destination`](crate::types::S3Destination).
    pub fn builder() -> crate::types::builders::S3DestinationBuilder {
        crate::types::builders::S3DestinationBuilder::default()
    }
}

/// A builder for [`S3Destination`](crate::types::S3Destination).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3DestinationBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) object_key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3DestinationBuilder {
    /// <p>The name of an Amazon S3 bucket. For more information about buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-buckets-s3.html">Creating, configuring, and working with Amazon S3 buckets</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    /// This field is required.
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an Amazon S3 bucket. For more information about buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-buckets-s3.html">Creating, configuring, and working with Amazon S3 buckets</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>The name of an Amazon S3 bucket. For more information about buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-buckets-s3.html">Creating, configuring, and working with Amazon S3 buckets</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>A string prefix for an Amazon S3 object key. It's usually a folder name. For more information about folders in Amazon S3, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html">Organizing objects in the Amazon S3 console using folders</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn object_key_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object_key_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string prefix for an Amazon S3 object key. It's usually a folder name. For more information about folders in Amazon S3, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html">Organizing objects in the Amazon S3 console using folders</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn set_object_key_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object_key_prefix = input;
        self
    }
    /// <p>A string prefix for an Amazon S3 object key. It's usually a folder name. For more information about folders in Amazon S3, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html">Organizing objects in the Amazon S3 console using folders</a> in the <i>Amazon Simple Storage Service User Guide</i>.</p>
    pub fn get_object_key_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.object_key_prefix
    }
    /// Consumes the builder and constructs a [`S3Destination`](crate::types::S3Destination).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket_name`](crate::types::builders::S3DestinationBuilder::bucket_name)
    pub fn build(self) -> ::std::result::Result<crate::types::S3Destination, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3Destination {
            bucket_name: self.bucket_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket_name",
                    "bucket_name was not specified but it is required when building S3Destination",
                )
            })?,
            object_key_prefix: self.object_key_prefix,
        })
    }
}
