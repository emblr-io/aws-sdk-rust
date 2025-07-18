// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for the source S3 bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3ImportSource {
    /// <p>The URI for the source S3 bucket.</p>
    pub s3_location_uri: ::std::string::String,
    /// <p>The Region associated with the source S3 bucket.</p>
    pub s3_bucket_region: ::std::string::String,
    /// <p>The IAM ARN role used to access the source S3 bucket.</p>
    pub s3_bucket_access_role_arn: ::std::string::String,
}
impl S3ImportSource {
    /// <p>The URI for the source S3 bucket.</p>
    pub fn s3_location_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_location_uri.deref()
    }
    /// <p>The Region associated with the source S3 bucket.</p>
    pub fn s3_bucket_region(&self) -> &str {
        use std::ops::Deref;
        self.s3_bucket_region.deref()
    }
    /// <p>The IAM ARN role used to access the source S3 bucket.</p>
    pub fn s3_bucket_access_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.s3_bucket_access_role_arn.deref()
    }
}
impl S3ImportSource {
    /// Creates a new builder-style object to manufacture [`S3ImportSource`](crate::types::S3ImportSource).
    pub fn builder() -> crate::types::builders::S3ImportSourceBuilder {
        crate::types::builders::S3ImportSourceBuilder::default()
    }
}

/// A builder for [`S3ImportSource`](crate::types::S3ImportSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ImportSourceBuilder {
    pub(crate) s3_location_uri: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket_region: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl S3ImportSourceBuilder {
    /// <p>The URI for the source S3 bucket.</p>
    /// This field is required.
    pub fn s3_location_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_location_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI for the source S3 bucket.</p>
    pub fn set_s3_location_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_location_uri = input;
        self
    }
    /// <p>The URI for the source S3 bucket.</p>
    pub fn get_s3_location_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_location_uri
    }
    /// <p>The Region associated with the source S3 bucket.</p>
    /// This field is required.
    pub fn s3_bucket_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Region associated with the source S3 bucket.</p>
    pub fn set_s3_bucket_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_region = input;
        self
    }
    /// <p>The Region associated with the source S3 bucket.</p>
    pub fn get_s3_bucket_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_region
    }
    /// <p>The IAM ARN role used to access the source S3 bucket.</p>
    /// This field is required.
    pub fn s3_bucket_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM ARN role used to access the source S3 bucket.</p>
    pub fn set_s3_bucket_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_access_role_arn = input;
        self
    }
    /// <p>The IAM ARN role used to access the source S3 bucket.</p>
    pub fn get_s3_bucket_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_access_role_arn
    }
    /// Consumes the builder and constructs a [`S3ImportSource`](crate::types::S3ImportSource).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_location_uri`](crate::types::builders::S3ImportSourceBuilder::s3_location_uri)
    /// - [`s3_bucket_region`](crate::types::builders::S3ImportSourceBuilder::s3_bucket_region)
    /// - [`s3_bucket_access_role_arn`](crate::types::builders::S3ImportSourceBuilder::s3_bucket_access_role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::S3ImportSource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3ImportSource {
            s3_location_uri: self.s3_location_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_location_uri",
                    "s3_location_uri was not specified but it is required when building S3ImportSource",
                )
            })?,
            s3_bucket_region: self.s3_bucket_region.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_bucket_region",
                    "s3_bucket_region was not specified but it is required when building S3ImportSource",
                )
            })?,
            s3_bucket_access_role_arn: self.s3_bucket_access_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_bucket_access_role_arn",
                    "s3_bucket_access_role_arn was not specified but it is required when building S3ImportSource",
                )
            })?,
        })
    }
}
