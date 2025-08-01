// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecordHandlerProgressInput {
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub bearer_token: ::std::option::Option<::std::string::String>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub operation_status: ::std::option::Option<crate::types::OperationStatus>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub current_operation_status: ::std::option::Option<crate::types::OperationStatus>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub error_code: ::std::option::Option<crate::types::HandlerErrorCode>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub resource_model: ::std::option::Option<::std::string::String>,
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl RecordHandlerProgressInput {
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn bearer_token(&self) -> ::std::option::Option<&str> {
        self.bearer_token.as_deref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn operation_status(&self) -> ::std::option::Option<&crate::types::OperationStatus> {
        self.operation_status.as_ref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn current_operation_status(&self) -> ::std::option::Option<&crate::types::OperationStatus> {
        self.current_operation_status.as_ref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::HandlerErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn resource_model(&self) -> ::std::option::Option<&str> {
        self.resource_model.as_deref()
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl RecordHandlerProgressInput {
    /// Creates a new builder-style object to manufacture [`RecordHandlerProgressInput`](crate::operation::record_handler_progress::RecordHandlerProgressInput).
    pub fn builder() -> crate::operation::record_handler_progress::builders::RecordHandlerProgressInputBuilder {
        crate::operation::record_handler_progress::builders::RecordHandlerProgressInputBuilder::default()
    }
}

/// A builder for [`RecordHandlerProgressInput`](crate::operation::record_handler_progress::RecordHandlerProgressInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecordHandlerProgressInputBuilder {
    pub(crate) bearer_token: ::std::option::Option<::std::string::String>,
    pub(crate) operation_status: ::std::option::Option<crate::types::OperationStatus>,
    pub(crate) current_operation_status: ::std::option::Option<crate::types::OperationStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::HandlerErrorCode>,
    pub(crate) resource_model: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl RecordHandlerProgressInputBuilder {
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    /// This field is required.
    pub fn bearer_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bearer_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_bearer_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bearer_token = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_bearer_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.bearer_token
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    /// This field is required.
    pub fn operation_status(mut self, input: crate::types::OperationStatus) -> Self {
        self.operation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_operation_status(mut self, input: ::std::option::Option<crate::types::OperationStatus>) -> Self {
        self.operation_status = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_operation_status(&self) -> &::std::option::Option<crate::types::OperationStatus> {
        &self.operation_status
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn current_operation_status(mut self, input: crate::types::OperationStatus) -> Self {
        self.current_operation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_current_operation_status(mut self, input: ::std::option::Option<crate::types::OperationStatus>) -> Self {
        self.current_operation_status = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_current_operation_status(&self) -> &::std::option::Option<crate::types::OperationStatus> {
        &self.current_operation_status
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn error_code(mut self, input: crate::types::HandlerErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::HandlerErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::HandlerErrorCode> {
        &self.error_code
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn resource_model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_resource_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_model = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_resource_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_model
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Reserved for use by the <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/what-is-cloudformation-cli.html">CloudFormation CLI</a>.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`RecordHandlerProgressInput`](crate::operation::record_handler_progress::RecordHandlerProgressInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::record_handler_progress::RecordHandlerProgressInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::record_handler_progress::RecordHandlerProgressInput {
            bearer_token: self.bearer_token,
            operation_status: self.operation_status,
            current_operation_status: self.current_operation_status,
            status_message: self.status_message,
            error_code: self.error_code,
            resource_model: self.resource_model,
            client_request_token: self.client_request_token,
        })
    }
}
