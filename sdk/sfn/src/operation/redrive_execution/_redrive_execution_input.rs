// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RedriveExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the execution to be redriven.</p>
    pub execution_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don’t specify a client token, the Amazon Web Services SDK automatically generates a client token and uses it for the request to ensure idempotency. The API will return idempotent responses for the last 10 client tokens used to successfully redrive the execution. These client tokens are valid for up to 15 minutes after they are first used.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl RedriveExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the execution to be redriven.</p>
    pub fn execution_arn(&self) -> ::std::option::Option<&str> {
        self.execution_arn.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don’t specify a client token, the Amazon Web Services SDK automatically generates a client token and uses it for the request to ensure idempotency. The API will return idempotent responses for the last 10 client tokens used to successfully redrive the execution. These client tokens are valid for up to 15 minutes after they are first used.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl RedriveExecutionInput {
    /// Creates a new builder-style object to manufacture [`RedriveExecutionInput`](crate::operation::redrive_execution::RedriveExecutionInput).
    pub fn builder() -> crate::operation::redrive_execution::builders::RedriveExecutionInputBuilder {
        crate::operation::redrive_execution::builders::RedriveExecutionInputBuilder::default()
    }
}

/// A builder for [`RedriveExecutionInput`](crate::operation::redrive_execution::RedriveExecutionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RedriveExecutionInputBuilder {
    pub(crate) execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl RedriveExecutionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the execution to be redriven.</p>
    /// This field is required.
    pub fn execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution to be redriven.</p>
    pub fn set_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution to be redriven.</p>
    pub fn get_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_arn
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don’t specify a client token, the Amazon Web Services SDK automatically generates a client token and uses it for the request to ensure idempotency. The API will return idempotent responses for the last 10 client tokens used to successfully redrive the execution. These client tokens are valid for up to 15 minutes after they are first used.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don’t specify a client token, the Amazon Web Services SDK automatically generates a client token and uses it for the request to ensure idempotency. The API will return idempotent responses for the last 10 client tokens used to successfully redrive the execution. These client tokens are valid for up to 15 minutes after they are first used.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you don’t specify a client token, the Amazon Web Services SDK automatically generates a client token and uses it for the request to ensure idempotency. The API will return idempotent responses for the last 10 client tokens used to successfully redrive the execution. These client tokens are valid for up to 15 minutes after they are first used.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`RedriveExecutionInput`](crate::operation::redrive_execution::RedriveExecutionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::redrive_execution::RedriveExecutionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::redrive_execution::RedriveExecutionInput {
            execution_arn: self.execution_arn,
            client_token: self.client_token,
        })
    }
}
