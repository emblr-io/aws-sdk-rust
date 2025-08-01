// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartChangeRequestExecutionOutput {
    /// <p>The unique ID of a runbook workflow operation. (A runbook workflow is a type of Automation operation.)</p>
    pub automation_execution_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartChangeRequestExecutionOutput {
    /// <p>The unique ID of a runbook workflow operation. (A runbook workflow is a type of Automation operation.)</p>
    pub fn automation_execution_id(&self) -> ::std::option::Option<&str> {
        self.automation_execution_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartChangeRequestExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartChangeRequestExecutionOutput {
    /// Creates a new builder-style object to manufacture [`StartChangeRequestExecutionOutput`](crate::operation::start_change_request_execution::StartChangeRequestExecutionOutput).
    pub fn builder() -> crate::operation::start_change_request_execution::builders::StartChangeRequestExecutionOutputBuilder {
        crate::operation::start_change_request_execution::builders::StartChangeRequestExecutionOutputBuilder::default()
    }
}

/// A builder for [`StartChangeRequestExecutionOutput`](crate::operation::start_change_request_execution::StartChangeRequestExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartChangeRequestExecutionOutputBuilder {
    pub(crate) automation_execution_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartChangeRequestExecutionOutputBuilder {
    /// <p>The unique ID of a runbook workflow operation. (A runbook workflow is a type of Automation operation.)</p>
    pub fn automation_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.automation_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of a runbook workflow operation. (A runbook workflow is a type of Automation operation.)</p>
    pub fn set_automation_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.automation_execution_id = input;
        self
    }
    /// <p>The unique ID of a runbook workflow operation. (A runbook workflow is a type of Automation operation.)</p>
    pub fn get_automation_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.automation_execution_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartChangeRequestExecutionOutput`](crate::operation::start_change_request_execution::StartChangeRequestExecutionOutput).
    pub fn build(self) -> crate::operation::start_change_request_execution::StartChangeRequestExecutionOutput {
        crate::operation::start_change_request_execution::StartChangeRequestExecutionOutput {
            automation_execution_id: self.automation_execution_id,
            _request_id: self._request_id,
        }
    }
}
