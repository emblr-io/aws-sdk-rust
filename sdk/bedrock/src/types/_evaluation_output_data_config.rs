// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon S3 location where the results of your evaluation job are saved.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluationOutputDataConfig {
    /// <p>The Amazon S3 URI where the results of the evaluation job are saved.</p>
    pub s3_uri: ::std::string::String,
}
impl EvaluationOutputDataConfig {
    /// <p>The Amazon S3 URI where the results of the evaluation job are saved.</p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
}
impl EvaluationOutputDataConfig {
    /// Creates a new builder-style object to manufacture [`EvaluationOutputDataConfig`](crate::types::EvaluationOutputDataConfig).
    pub fn builder() -> crate::types::builders::EvaluationOutputDataConfigBuilder {
        crate::types::builders::EvaluationOutputDataConfigBuilder::default()
    }
}

/// A builder for [`EvaluationOutputDataConfig`](crate::types::EvaluationOutputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluationOutputDataConfigBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
}
impl EvaluationOutputDataConfigBuilder {
    /// <p>The Amazon S3 URI where the results of the evaluation job are saved.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 URI where the results of the evaluation job are saved.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The Amazon S3 URI where the results of the evaluation job are saved.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// Consumes the builder and constructs a [`EvaluationOutputDataConfig`](crate::types::EvaluationOutputDataConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_uri`](crate::types::builders::EvaluationOutputDataConfigBuilder::s3_uri)
    pub fn build(self) -> ::std::result::Result<crate::types::EvaluationOutputDataConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EvaluationOutputDataConfig {
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building EvaluationOutputDataConfig",
                )
            })?,
        })
    }
}
