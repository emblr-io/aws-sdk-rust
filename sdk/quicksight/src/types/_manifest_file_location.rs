// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Amazon S3 manifest file location.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ManifestFileLocation {
    /// <p>Amazon S3 bucket.</p>
    pub bucket: ::std::string::String,
    /// <p>Amazon S3 key that identifies an object.</p>
    pub key: ::std::string::String,
}
impl ManifestFileLocation {
    /// <p>Amazon S3 bucket.</p>
    pub fn bucket(&self) -> &str {
        use std::ops::Deref;
        self.bucket.deref()
    }
    /// <p>Amazon S3 key that identifies an object.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
}
impl ManifestFileLocation {
    /// Creates a new builder-style object to manufacture [`ManifestFileLocation`](crate::types::ManifestFileLocation).
    pub fn builder() -> crate::types::builders::ManifestFileLocationBuilder {
        crate::types::builders::ManifestFileLocationBuilder::default()
    }
}

/// A builder for [`ManifestFileLocation`](crate::types::ManifestFileLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ManifestFileLocationBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl ManifestFileLocationBuilder {
    /// <p>Amazon S3 bucket.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon S3 bucket.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>Amazon S3 bucket.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>Amazon S3 key that identifies an object.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon S3 key that identifies an object.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>Amazon S3 key that identifies an object.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`ManifestFileLocation`](crate::types::ManifestFileLocation).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket`](crate::types::builders::ManifestFileLocationBuilder::bucket)
    /// - [`key`](crate::types::builders::ManifestFileLocationBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::ManifestFileLocation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ManifestFileLocation {
            bucket: self.bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket",
                    "bucket was not specified but it is required when building ManifestFileLocation",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building ManifestFileLocation",
                )
            })?,
        })
    }
}
