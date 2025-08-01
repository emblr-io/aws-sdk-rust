// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>S3 configuration for storing log data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Config {
    /// <p>S3 bucket name.</p>
    pub bucket_name: ::std::string::String,
    /// <p>S3 prefix.</p>
    pub key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3Config {
    /// <p>S3 bucket name.</p>
    pub fn bucket_name(&self) -> &str {
        use std::ops::Deref;
        self.bucket_name.deref()
    }
    /// <p>S3 prefix.</p>
    pub fn key_prefix(&self) -> ::std::option::Option<&str> {
        self.key_prefix.as_deref()
    }
}
impl S3Config {
    /// Creates a new builder-style object to manufacture [`S3Config`](crate::types::S3Config).
    pub fn builder() -> crate::types::builders::S3ConfigBuilder {
        crate::types::builders::S3ConfigBuilder::default()
    }
}

/// A builder for [`S3Config`](crate::types::S3Config).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ConfigBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) key_prefix: ::std::option::Option<::std::string::String>,
}
impl S3ConfigBuilder {
    /// <p>S3 bucket name.</p>
    /// This field is required.
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>S3 bucket name.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>S3 bucket name.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>S3 prefix.</p>
    pub fn key_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>S3 prefix.</p>
    pub fn set_key_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_prefix = input;
        self
    }
    /// <p>S3 prefix.</p>
    pub fn get_key_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_prefix
    }
    /// Consumes the builder and constructs a [`S3Config`](crate::types::S3Config).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket_name`](crate::types::builders::S3ConfigBuilder::bucket_name)
    pub fn build(self) -> ::std::result::Result<crate::types::S3Config, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3Config {
            bucket_name: self.bucket_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket_name",
                    "bucket_name was not specified but it is required when building S3Config",
                )
            })?,
            key_prefix: self.key_prefix,
        })
    }
}
