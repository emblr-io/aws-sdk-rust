// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>CancelWorkflowExecution</code> decision.</p>
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
pub struct CancelWorkflowExecutionDecisionAttributes {
    /// <p>Details of the cancellation.</p>
    pub details: ::std::option::Option<::std::string::String>,
}
impl CancelWorkflowExecutionDecisionAttributes {
    /// <p>Details of the cancellation.</p>
    pub fn details(&self) -> ::std::option::Option<&str> {
        self.details.as_deref()
    }
}
impl CancelWorkflowExecutionDecisionAttributes {
    /// Creates a new builder-style object to manufacture [`CancelWorkflowExecutionDecisionAttributes`](crate::types::CancelWorkflowExecutionDecisionAttributes).
    pub fn builder() -> crate::types::builders::CancelWorkflowExecutionDecisionAttributesBuilder {
        crate::types::builders::CancelWorkflowExecutionDecisionAttributesBuilder::default()
    }
}

/// A builder for [`CancelWorkflowExecutionDecisionAttributes`](crate::types::CancelWorkflowExecutionDecisionAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelWorkflowExecutionDecisionAttributesBuilder {
    pub(crate) details: ::std::option::Option<::std::string::String>,
}
impl CancelWorkflowExecutionDecisionAttributesBuilder {
    /// <p>Details of the cancellation.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Details of the cancellation.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>Details of the cancellation.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.details
    }
    /// Consumes the builder and constructs a [`CancelWorkflowExecutionDecisionAttributes`](crate::types::CancelWorkflowExecutionDecisionAttributes).
    pub fn build(self) -> crate::types::CancelWorkflowExecutionDecisionAttributes {
        crate::types::CancelWorkflowExecutionDecisionAttributes { details: self.details }
    }
}
