// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>RequestCancelExternalWorkflowExecution</code> decision.</p>
/// <p><b>Access Control</b></p>
/// <p>You can use IAM policies to control this decision's access to Amazon SWF resources as follows:</p>
/// <ul>
/// <li>
/// <p>Use a <code>Resource</code> element with the domain name to limit the action to only specified domains.</p></li>
/// <li>
/// <p>Use an <code>Action</code> element to allow or deny permission to call this action.</p></li>
/// <li>
/// <p>You cannot use an IAM policy to constrain this action's parameters.</p></li>
/// </ul>
/// <p>If the caller doesn't have sufficient permissions to invoke the action, or the parameter values fall outside the specified constraints, the action fails. The associated event attribute's <code>cause</code> parameter is set to <code>OPERATION_NOT_PERMITTED</code>. For details and example IAM policies, see <a href="https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-dev-iam.html">Using IAM to Manage Access to Amazon SWF Workflows</a> in the <i>Amazon SWF Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestCancelExternalWorkflowExecutionDecisionAttributes {
    /// <p>The <code>workflowId</code> of the external workflow execution to cancel.</p>
    pub workflow_id: ::std::string::String,
    /// <p>The <code>runId</code> of the external workflow execution to cancel.</p>
    pub run_id: ::std::option::Option<::std::string::String>,
    /// <p>The data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub control: ::std::option::Option<::std::string::String>,
}
impl RequestCancelExternalWorkflowExecutionDecisionAttributes {
    /// <p>The <code>workflowId</code> of the external workflow execution to cancel.</p>
    pub fn workflow_id(&self) -> &str {
        use std::ops::Deref;
        self.workflow_id.deref()
    }
    /// <p>The <code>runId</code> of the external workflow execution to cancel.</p>
    pub fn run_id(&self) -> ::std::option::Option<&str> {
        self.run_id.as_deref()
    }
    /// <p>The data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn control(&self) -> ::std::option::Option<&str> {
        self.control.as_deref()
    }
}
impl RequestCancelExternalWorkflowExecutionDecisionAttributes {
    /// Creates a new builder-style object to manufacture [`RequestCancelExternalWorkflowExecutionDecisionAttributes`](crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes).
    pub fn builder() -> crate::types::builders::RequestCancelExternalWorkflowExecutionDecisionAttributesBuilder {
        crate::types::builders::RequestCancelExternalWorkflowExecutionDecisionAttributesBuilder::default()
    }
}

/// A builder for [`RequestCancelExternalWorkflowExecutionDecisionAttributes`](crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestCancelExternalWorkflowExecutionDecisionAttributesBuilder {
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
    pub(crate) control: ::std::option::Option<::std::string::String>,
}
impl RequestCancelExternalWorkflowExecutionDecisionAttributesBuilder {
    /// <p>The <code>workflowId</code> of the external workflow execution to cancel.</p>
    /// This field is required.
    pub fn workflow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>workflowId</code> of the external workflow execution to cancel.</p>
    pub fn set_workflow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_id = input;
        self
    }
    /// <p>The <code>workflowId</code> of the external workflow execution to cancel.</p>
    pub fn get_workflow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_id
    }
    /// <p>The <code>runId</code> of the external workflow execution to cancel.</p>
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>runId</code> of the external workflow execution to cancel.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>The <code>runId</code> of the external workflow execution to cancel.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    /// <p>The data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn control(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn set_control(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control = input;
        self
    }
    /// <p>The data attached to the event that can be used by the decider in subsequent workflow tasks.</p>
    pub fn get_control(&self) -> &::std::option::Option<::std::string::String> {
        &self.control
    }
    /// Consumes the builder and constructs a [`RequestCancelExternalWorkflowExecutionDecisionAttributes`](crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`workflow_id`](crate::types::builders::RequestCancelExternalWorkflowExecutionDecisionAttributesBuilder::workflow_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::RequestCancelExternalWorkflowExecutionDecisionAttributes {
            workflow_id: self.workflow_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workflow_id",
                    "workflow_id was not specified but it is required when building RequestCancelExternalWorkflowExecutionDecisionAttributes",
                )
            })?,
            run_id: self.run_id,
            control: self.control,
        })
    }
}
