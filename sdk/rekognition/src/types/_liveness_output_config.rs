// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains settings that specify the location of an Amazon S3 bucket used to store the output of a Face Liveness session. Note that the S3 bucket must be located in the caller's AWS account and in the same region as the Face Liveness end-point. Additionally, the Amazon S3 object keys are auto-generated by the Face Liveness system.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LivenessOutputConfig {
    /// <p>The path to an AWS Amazon S3 bucket used to store Face Liveness session results.</p>
    pub s3_bucket: ::std::string::String,
    /// <p>The prefix prepended to the output files for the Face Liveness session results.</p>
    pub s3_key_prefix: ::std::option::Option<::std::string::String>,
}
impl LivenessOutputConfig {
    /// <p>The path to an AWS Amazon S3 bucket used to store Face Liveness session results.</p>
    pub fn s3_bucket(&self) -> &str {
        use std::ops::Deref;
        self.s3_bucket.deref()
    }
    /// <p>The prefix prepended to the output files for the Face Liveness session results.</p>
    pub fn s3_key_prefix(&self) -> ::std::option::Option<&str> {
        self.s3_key_prefix.as_deref()
    }
}
impl LivenessOutputConfig {
    /// Creates a new builder-style object to manufacture [`LivenessOutputConfig`](crate::types::LivenessOutputConfig).
    pub fn builder() -> crate::types::builders::LivenessOutputConfigBuilder {
        crate::types::builders::LivenessOutputConfigBuilder::default()
    }
}

/// A builder for [`LivenessOutputConfig`](crate::types::LivenessOutputConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LivenessOutputConfigBuilder {
    pub(crate) s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key_prefix: ::std::option::Option<::std::string::String>,
}
impl LivenessOutputConfigBuilder {
    /// <p>The path to an AWS Amazon S3 bucket used to store Face Liveness session results.</p>
    /// This field is required.
    pub fn s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to an AWS Amazon S3 bucket used to store Face Liveness session results.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>The path to an AWS Amazon S3 bucket used to store Face Liveness session results.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket
    }
    /// <p>The prefix prepended to the output files for the Face Liveness session results.</p>
    pub fn s3_key_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix prepended to the output files for the Face Liveness session results.</p>
    pub fn set_s3_key_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key_prefix = input;
        self
    }
    /// <p>The prefix prepended to the output files for the Face Liveness session results.</p>
    pub fn get_s3_key_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key_prefix
    }
    /// Consumes the builder and constructs a [`LivenessOutputConfig`](crate::types::LivenessOutputConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_bucket`](crate::types::builders::LivenessOutputConfigBuilder::s3_bucket)
    pub fn build(self) -> ::std::result::Result<crate::types::LivenessOutputConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LivenessOutputConfig {
            s3_bucket: self.s3_bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_bucket",
                    "s3_bucket was not specified but it is required when building LivenessOutputConfig",
                )
            })?,
            s3_key_prefix: self.s3_key_prefix,
        })
    }
}
