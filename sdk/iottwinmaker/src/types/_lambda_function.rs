// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Lambda function.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LambdaFunction {
    /// <p>The ARN of the Lambda function.</p>
    pub arn: ::std::string::String,
}
impl LambdaFunction {
    /// <p>The ARN of the Lambda function.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
}
impl LambdaFunction {
    /// Creates a new builder-style object to manufacture [`LambdaFunction`](crate::types::LambdaFunction).
    pub fn builder() -> crate::types::builders::LambdaFunctionBuilder {
        crate::types::builders::LambdaFunctionBuilder::default()
    }
}

/// A builder for [`LambdaFunction`](crate::types::LambdaFunction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LambdaFunctionBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl LambdaFunctionBuilder {
    /// <p>The ARN of the Lambda function.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Lambda function.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the Lambda function.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`LambdaFunction`](crate::types::LambdaFunction).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::LambdaFunctionBuilder::arn)
    pub fn build(self) -> ::std::result::Result<crate::types::LambdaFunction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LambdaFunction {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building LambdaFunction",
                )
            })?,
        })
    }
}
