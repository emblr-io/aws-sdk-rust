// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The S3 location where Identity Resolution Jobs write result files.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3ExportingLocation {
    /// <p>The name of the S3 bucket name where Identity Resolution Jobs write result files.</p>
    pub s3_bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>The S3 key name of the location where Identity Resolution Jobs write result files.</p>
    pub s3_key_name: ::std::option::Option<::std::string::String>,
}
impl S3ExportingLocation {
    /// <p>The name of the S3 bucket name where Identity Resolution Jobs write result files.</p>
    pub fn s3_bucket_name(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_name.as_deref()
    }
    /// <p>The S3 key name of the location where Identity Resolution Jobs write result files.</p>
    pub fn s3_key_name(&self) -> ::std::option::Option<&str> {
        self.s3_key_name.as_deref()
    }
}
impl S3ExportingLocation {
    /// Creates a new builder-style object to manufacture [`S3ExportingLocation`](crate::types::S3ExportingLocation).
    pub fn builder() -> crate::types::builders::S3ExportingLocationBuilder {
        crate::types::builders::S3ExportingLocationBuilder::default()
    }
}

/// A builder for [`S3ExportingLocation`](crate::types::S3ExportingLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ExportingLocationBuilder {
    pub(crate) s3_bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key_name: ::std::option::Option<::std::string::String>,
}
impl S3ExportingLocationBuilder {
    /// <p>The name of the S3 bucket name where Identity Resolution Jobs write result files.</p>
    pub fn s3_bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the S3 bucket name where Identity Resolution Jobs write result files.</p>
    pub fn set_s3_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_name = input;
        self
    }
    /// <p>The name of the S3 bucket name where Identity Resolution Jobs write result files.</p>
    pub fn get_s3_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_name
    }
    /// <p>The S3 key name of the location where Identity Resolution Jobs write result files.</p>
    pub fn s3_key_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 key name of the location where Identity Resolution Jobs write result files.</p>
    pub fn set_s3_key_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key_name = input;
        self
    }
    /// <p>The S3 key name of the location where Identity Resolution Jobs write result files.</p>
    pub fn get_s3_key_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key_name
    }
    /// Consumes the builder and constructs a [`S3ExportingLocation`](crate::types::S3ExportingLocation).
    pub fn build(self) -> crate::types::S3ExportingLocation {
        crate::types::S3ExportingLocation {
            s3_bucket_name: self.s3_bucket_name,
            s3_key_name: self.s3_key_name,
        }
    }
}
