// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Lambda data source configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LambdaDataSourceConfig {
    /// <p>The Amazon Resource Name (ARN) for the Lambda function.</p>
    pub lambda_function_arn: ::std::string::String,
}
impl LambdaDataSourceConfig {
    /// <p>The Amazon Resource Name (ARN) for the Lambda function.</p>
    pub fn lambda_function_arn(&self) -> &str {
        use std::ops::Deref;
        self.lambda_function_arn.deref()
    }
}
impl LambdaDataSourceConfig {
    /// Creates a new builder-style object to manufacture [`LambdaDataSourceConfig`](crate::types::LambdaDataSourceConfig).
    pub fn builder() -> crate::types::builders::LambdaDataSourceConfigBuilder {
        crate::types::builders::LambdaDataSourceConfigBuilder::default()
    }
}

/// A builder for [`LambdaDataSourceConfig`](crate::types::LambdaDataSourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LambdaDataSourceConfigBuilder {
    pub(crate) lambda_function_arn: ::std::option::Option<::std::string::String>,
}
impl LambdaDataSourceConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) for the Lambda function.</p>
    /// This field is required.
    pub fn lambda_function_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lambda_function_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the Lambda function.</p>
    pub fn set_lambda_function_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lambda_function_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the Lambda function.</p>
    pub fn get_lambda_function_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.lambda_function_arn
    }
    /// Consumes the builder and constructs a [`LambdaDataSourceConfig`](crate::types::LambdaDataSourceConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`lambda_function_arn`](crate::types::builders::LambdaDataSourceConfigBuilder::lambda_function_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::LambdaDataSourceConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LambdaDataSourceConfig {
            lambda_function_arn: self.lambda_function_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "lambda_function_arn",
                    "lambda_function_arn was not specified but it is required when building LambdaDataSourceConfig",
                )
            })?,
        })
    }
}
