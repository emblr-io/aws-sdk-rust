// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for the Lambda endpoint type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LambdaEndpointConfig {
    /// <p>The Amazon Resource Name (ARN) of the Lambda endpoint.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl LambdaEndpointConfig {
    /// <p>The Amazon Resource Name (ARN) of the Lambda endpoint.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl LambdaEndpointConfig {
    /// Creates a new builder-style object to manufacture [`LambdaEndpointConfig`](crate::types::LambdaEndpointConfig).
    pub fn builder() -> crate::types::builders::LambdaEndpointConfigBuilder {
        crate::types::builders::LambdaEndpointConfigBuilder::default()
    }
}

/// A builder for [`LambdaEndpointConfig`](crate::types::LambdaEndpointConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LambdaEndpointConfigBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl LambdaEndpointConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Lambda endpoint.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda endpoint.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda endpoint.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`LambdaEndpointConfig`](crate::types::LambdaEndpointConfig).
    pub fn build(self) -> crate::types::LambdaEndpointConfig {
        crate::types::LambdaEndpointConfig { arn: self.arn }
    }
}
