// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information that defines a schema conversion application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScApplicationAttributes {
    /// <p>The path for the Amazon S3 bucket that the application uses for exporting assessment reports.</p>
    pub s3_bucket_path: ::std::option::Option<::std::string::String>,
    /// <p>The ARN for the role the application uses to access its Amazon S3 bucket.</p>
    pub s3_bucket_role_arn: ::std::option::Option<::std::string::String>,
}
impl ScApplicationAttributes {
    /// <p>The path for the Amazon S3 bucket that the application uses for exporting assessment reports.</p>
    pub fn s3_bucket_path(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_path.as_deref()
    }
    /// <p>The ARN for the role the application uses to access its Amazon S3 bucket.</p>
    pub fn s3_bucket_role_arn(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_role_arn.as_deref()
    }
}
impl ScApplicationAttributes {
    /// Creates a new builder-style object to manufacture [`ScApplicationAttributes`](crate::types::ScApplicationAttributes).
    pub fn builder() -> crate::types::builders::ScApplicationAttributesBuilder {
        crate::types::builders::ScApplicationAttributesBuilder::default()
    }
}

/// A builder for [`ScApplicationAttributes`](crate::types::ScApplicationAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScApplicationAttributesBuilder {
    pub(crate) s3_bucket_path: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket_role_arn: ::std::option::Option<::std::string::String>,
}
impl ScApplicationAttributesBuilder {
    /// <p>The path for the Amazon S3 bucket that the application uses for exporting assessment reports.</p>
    pub fn s3_bucket_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path for the Amazon S3 bucket that the application uses for exporting assessment reports.</p>
    pub fn set_s3_bucket_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_path = input;
        self
    }
    /// <p>The path for the Amazon S3 bucket that the application uses for exporting assessment reports.</p>
    pub fn get_s3_bucket_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_path
    }
    /// <p>The ARN for the role the application uses to access its Amazon S3 bucket.</p>
    pub fn s3_bucket_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the role the application uses to access its Amazon S3 bucket.</p>
    pub fn set_s3_bucket_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_role_arn = input;
        self
    }
    /// <p>The ARN for the role the application uses to access its Amazon S3 bucket.</p>
    pub fn get_s3_bucket_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_role_arn
    }
    /// Consumes the builder and constructs a [`ScApplicationAttributes`](crate::types::ScApplicationAttributes).
    pub fn build(self) -> crate::types::ScApplicationAttributes {
        crate::types::ScApplicationAttributes {
            s3_bucket_path: self.s3_bucket_path,
            s3_bucket_role_arn: self.s3_bucket_role_arn,
        }
    }
}
