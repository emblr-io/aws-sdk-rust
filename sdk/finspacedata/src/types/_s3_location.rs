// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The location of an external Dataview in an S3 bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Location {
    /// <p>The name of the S3 bucket.</p>
    pub bucket: ::std::string::String,
    /// <p>The path of the folder, within the S3 bucket that contains the Dataset.</p>
    pub key: ::std::string::String,
}
impl S3Location {
    /// <p>The name of the S3 bucket.</p>
    pub fn bucket(&self) -> &str {
        use std::ops::Deref;
        self.bucket.deref()
    }
    /// <p>The path of the folder, within the S3 bucket that contains the Dataset.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
}
impl S3Location {
    /// Creates a new builder-style object to manufacture [`S3Location`](crate::types::S3Location).
    pub fn builder() -> crate::types::builders::S3LocationBuilder {
        crate::types::builders::S3LocationBuilder::default()
    }
}

/// A builder for [`S3Location`](crate::types::S3Location).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3LocationBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl S3LocationBuilder {
    /// <p>The name of the S3 bucket.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the S3 bucket.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the S3 bucket.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The path of the folder, within the S3 bucket that contains the Dataset.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path of the folder, within the S3 bucket that contains the Dataset.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The path of the folder, within the S3 bucket that contains the Dataset.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`S3Location`](crate::types::S3Location).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket`](crate::types::builders::S3LocationBuilder::bucket)
    /// - [`key`](crate::types::builders::S3LocationBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::S3Location, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3Location {
            bucket: self.bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket",
                    "bucket was not specified but it is required when building S3Location",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building S3Location",
                )
            })?,
        })
    }
}
