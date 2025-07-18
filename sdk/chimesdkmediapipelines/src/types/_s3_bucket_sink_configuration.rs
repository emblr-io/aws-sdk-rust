// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration settings for the S3 bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct S3BucketSinkConfiguration {
    /// <p>The destination URL of the S3 bucket.</p>
    pub destination: ::std::string::String,
}
impl S3BucketSinkConfiguration {
    /// <p>The destination URL of the S3 bucket.</p>
    pub fn destination(&self) -> &str {
        use std::ops::Deref;
        self.destination.deref()
    }
}
impl ::std::fmt::Debug for S3BucketSinkConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("S3BucketSinkConfiguration");
        formatter.field("destination", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl S3BucketSinkConfiguration {
    /// Creates a new builder-style object to manufacture [`S3BucketSinkConfiguration`](crate::types::S3BucketSinkConfiguration).
    pub fn builder() -> crate::types::builders::S3BucketSinkConfigurationBuilder {
        crate::types::builders::S3BucketSinkConfigurationBuilder::default()
    }
}

/// A builder for [`S3BucketSinkConfiguration`](crate::types::S3BucketSinkConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct S3BucketSinkConfigurationBuilder {
    pub(crate) destination: ::std::option::Option<::std::string::String>,
}
impl S3BucketSinkConfigurationBuilder {
    /// <p>The destination URL of the S3 bucket.</p>
    /// This field is required.
    pub fn destination(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The destination URL of the S3 bucket.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The destination URL of the S3 bucket.</p>
    pub fn get_destination(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination
    }
    /// Consumes the builder and constructs a [`S3BucketSinkConfiguration`](crate::types::S3BucketSinkConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`destination`](crate::types::builders::S3BucketSinkConfigurationBuilder::destination)
    pub fn build(self) -> ::std::result::Result<crate::types::S3BucketSinkConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3BucketSinkConfiguration {
            destination: self.destination.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "destination",
                    "destination was not specified but it is required when building S3BucketSinkConfiguration",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for S3BucketSinkConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("S3BucketSinkConfigurationBuilder");
        formatter.field("destination", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
