// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that describes an S3 location where recorded videos will be stored.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3StorageConfiguration {
    /// <p>Location (S3 bucket name) where recorded videos will be stored. Note that the StorageConfiguration and S3 bucket must be in the same region as the Composition.</p>
    pub bucket_name: ::std::string::String,
}
impl S3StorageConfiguration {
    /// <p>Location (S3 bucket name) where recorded videos will be stored. Note that the StorageConfiguration and S3 bucket must be in the same region as the Composition.</p>
    pub fn bucket_name(&self) -> &str {
        use std::ops::Deref;
        self.bucket_name.deref()
    }
}
impl S3StorageConfiguration {
    /// Creates a new builder-style object to manufacture [`S3StorageConfiguration`](crate::types::S3StorageConfiguration).
    pub fn builder() -> crate::types::builders::S3StorageConfigurationBuilder {
        crate::types::builders::S3StorageConfigurationBuilder::default()
    }
}

/// A builder for [`S3StorageConfiguration`](crate::types::S3StorageConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3StorageConfigurationBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
}
impl S3StorageConfigurationBuilder {
    /// <p>Location (S3 bucket name) where recorded videos will be stored. Note that the StorageConfiguration and S3 bucket must be in the same region as the Composition.</p>
    /// This field is required.
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Location (S3 bucket name) where recorded videos will be stored. Note that the StorageConfiguration and S3 bucket must be in the same region as the Composition.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>Location (S3 bucket name) where recorded videos will be stored. Note that the StorageConfiguration and S3 bucket must be in the same region as the Composition.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// Consumes the builder and constructs a [`S3StorageConfiguration`](crate::types::S3StorageConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket_name`](crate::types::builders::S3StorageConfigurationBuilder::bucket_name)
    pub fn build(self) -> ::std::result::Result<crate::types::S3StorageConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3StorageConfiguration {
            bucket_name: self.bucket_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket_name",
                    "bucket_name was not specified but it is required when building S3StorageConfiguration",
                )
            })?,
        })
    }
}
