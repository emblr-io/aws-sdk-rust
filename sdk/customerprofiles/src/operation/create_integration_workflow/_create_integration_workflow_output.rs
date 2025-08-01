// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIntegrationWorkflowOutput {
    /// <p>Unique identifier for the workflow.</p>
    pub workflow_id: ::std::string::String,
    /// <p>A message indicating create request was received.</p>
    pub message: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateIntegrationWorkflowOutput {
    /// <p>Unique identifier for the workflow.</p>
    pub fn workflow_id(&self) -> &str {
        use std::ops::Deref;
        self.workflow_id.deref()
    }
    /// <p>A message indicating create request was received.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateIntegrationWorkflowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateIntegrationWorkflowOutput {
    /// Creates a new builder-style object to manufacture [`CreateIntegrationWorkflowOutput`](crate::operation::create_integration_workflow::CreateIntegrationWorkflowOutput).
    pub fn builder() -> crate::operation::create_integration_workflow::builders::CreateIntegrationWorkflowOutputBuilder {
        crate::operation::create_integration_workflow::builders::CreateIntegrationWorkflowOutputBuilder::default()
    }
}

/// A builder for [`CreateIntegrationWorkflowOutput`](crate::operation::create_integration_workflow::CreateIntegrationWorkflowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIntegrationWorkflowOutputBuilder {
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateIntegrationWorkflowOutputBuilder {
    /// <p>Unique identifier for the workflow.</p>
    /// This field is required.
    pub fn workflow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier for the workflow.</p>
    pub fn set_workflow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_id = input;
        self
    }
    /// <p>Unique identifier for the workflow.</p>
    pub fn get_workflow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_id
    }
    /// <p>A message indicating create request was received.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message indicating create request was received.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message indicating create request was received.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateIntegrationWorkflowOutput`](crate::operation::create_integration_workflow::CreateIntegrationWorkflowOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`workflow_id`](crate::operation::create_integration_workflow::builders::CreateIntegrationWorkflowOutputBuilder::workflow_id)
    /// - [`message`](crate::operation::create_integration_workflow::builders::CreateIntegrationWorkflowOutputBuilder::message)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_integration_workflow::CreateIntegrationWorkflowOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_integration_workflow::CreateIntegrationWorkflowOutput {
            workflow_id: self.workflow_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workflow_id",
                    "workflow_id was not specified but it is required when building CreateIntegrationWorkflowOutput",
                )
            })?,
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building CreateIntegrationWorkflowOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
