// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartCommandExecutionOutput {
    /// <p>A unique identifier for the command execution.</p>
    pub execution_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartCommandExecutionOutput {
    /// <p>A unique identifier for the command execution.</p>
    pub fn execution_id(&self) -> ::std::option::Option<&str> {
        self.execution_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartCommandExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartCommandExecutionOutput {
    /// Creates a new builder-style object to manufacture [`StartCommandExecutionOutput`](crate::operation::start_command_execution::StartCommandExecutionOutput).
    pub fn builder() -> crate::operation::start_command_execution::builders::StartCommandExecutionOutputBuilder {
        crate::operation::start_command_execution::builders::StartCommandExecutionOutputBuilder::default()
    }
}

/// A builder for [`StartCommandExecutionOutput`](crate::operation::start_command_execution::StartCommandExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartCommandExecutionOutputBuilder {
    pub(crate) execution_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartCommandExecutionOutputBuilder {
    /// <p>A unique identifier for the command execution.</p>
    pub fn execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the command execution.</p>
    pub fn set_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_id = input;
        self
    }
    /// <p>A unique identifier for the command execution.</p>
    pub fn get_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartCommandExecutionOutput`](crate::operation::start_command_execution::StartCommandExecutionOutput).
    pub fn build(self) -> crate::operation::start_command_execution::StartCommandExecutionOutput {
        crate::operation::start_command_execution::StartCommandExecutionOutput {
            execution_id: self.execution_id,
            _request_id: self._request_id,
        }
    }
}
