// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWorkflowOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateWorkflowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateWorkflowOutput {
    /// Creates a new builder-style object to manufacture [`UpdateWorkflowOutput`](crate::operation::update_workflow::UpdateWorkflowOutput).
    pub fn builder() -> crate::operation::update_workflow::builders::UpdateWorkflowOutputBuilder {
        crate::operation::update_workflow::builders::UpdateWorkflowOutputBuilder::default()
    }
}

/// A builder for [`UpdateWorkflowOutput`](crate::operation::update_workflow::UpdateWorkflowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWorkflowOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateWorkflowOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateWorkflowOutput`](crate::operation::update_workflow::UpdateWorkflowOutput).
    pub fn build(self) -> crate::operation::update_workflow::UpdateWorkflowOutput {
        crate::operation::update_workflow::UpdateWorkflowOutput {
            _request_id: self._request_id,
        }
    }
}
