// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestCancelWorkflowExecutionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RequestCancelWorkflowExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RequestCancelWorkflowExecutionOutput {
    /// Creates a new builder-style object to manufacture [`RequestCancelWorkflowExecutionOutput`](crate::operation::request_cancel_workflow_execution::RequestCancelWorkflowExecutionOutput).
    pub fn builder() -> crate::operation::request_cancel_workflow_execution::builders::RequestCancelWorkflowExecutionOutputBuilder {
        crate::operation::request_cancel_workflow_execution::builders::RequestCancelWorkflowExecutionOutputBuilder::default()
    }
}

/// A builder for [`RequestCancelWorkflowExecutionOutput`](crate::operation::request_cancel_workflow_execution::RequestCancelWorkflowExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestCancelWorkflowExecutionOutputBuilder {
    _request_id: Option<String>,
}
impl RequestCancelWorkflowExecutionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RequestCancelWorkflowExecutionOutput`](crate::operation::request_cancel_workflow_execution::RequestCancelWorkflowExecutionOutput).
    pub fn build(self) -> crate::operation::request_cancel_workflow_execution::RequestCancelWorkflowExecutionOutput {
        crate::operation::request_cancel_workflow_execution::RequestCancelWorkflowExecutionOutput {
            _request_id: self._request_id,
        }
    }
}
