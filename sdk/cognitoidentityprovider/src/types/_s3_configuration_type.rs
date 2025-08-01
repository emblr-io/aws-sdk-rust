// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration for the Amazon S3 bucket destination of user activity log export with threat protection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3ConfigurationType {
    /// <p>The ARN of an Amazon S3 bucket that's the destination for threat protection log export.</p>
    pub bucket_arn: ::std::option::Option<::std::string::String>,
}
impl S3ConfigurationType {
    /// <p>The ARN of an Amazon S3 bucket that's the destination for threat protection log export.</p>
    pub fn bucket_arn(&self) -> ::std::option::Option<&str> {
        self.bucket_arn.as_deref()
    }
}
impl S3ConfigurationType {
    /// Creates a new builder-style object to manufacture [`S3ConfigurationType`](crate::types::S3ConfigurationType).
    pub fn builder() -> crate::types::builders::S3ConfigurationTypeBuilder {
        crate::types::builders::S3ConfigurationTypeBuilder::default()
    }
}

/// A builder for [`S3ConfigurationType`](crate::types::S3ConfigurationType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ConfigurationTypeBuilder {
    pub(crate) bucket_arn: ::std::option::Option<::std::string::String>,
}
impl S3ConfigurationTypeBuilder {
    /// <p>The ARN of an Amazon S3 bucket that's the destination for threat protection log export.</p>
    pub fn bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of an Amazon S3 bucket that's the destination for threat protection log export.</p>
    pub fn set_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_arn = input;
        self
    }
    /// <p>The ARN of an Amazon S3 bucket that's the destination for threat protection log export.</p>
    pub fn get_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_arn
    }
    /// Consumes the builder and constructs a [`S3ConfigurationType`](crate::types::S3ConfigurationType).
    pub fn build(self) -> crate::types::S3ConfigurationType {
        crate::types::S3ConfigurationType { bucket_arn: self.bucket_arn }
    }
}
