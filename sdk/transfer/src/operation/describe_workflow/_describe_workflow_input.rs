// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkflowInput {
    /// <p>A unique identifier for the workflow.</p>
    pub workflow_id: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkflowInput {
    /// <p>A unique identifier for the workflow.</p>
    pub fn workflow_id(&self) -> ::std::option::Option<&str> {
        self.workflow_id.as_deref()
    }
}
impl DescribeWorkflowInput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkflowInput`](crate::operation::describe_workflow::DescribeWorkflowInput).
    pub fn builder() -> crate::operation::describe_workflow::builders::DescribeWorkflowInputBuilder {
        crate::operation::describe_workflow::builders::DescribeWorkflowInputBuilder::default()
    }
}

/// A builder for [`DescribeWorkflowInput`](crate::operation::describe_workflow::DescribeWorkflowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkflowInputBuilder {
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkflowInputBuilder {
    /// <p>A unique identifier for the workflow.</p>
    /// This field is required.
    pub fn workflow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workflow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the workflow.</p>
    pub fn set_workflow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workflow_id = input;
        self
    }
    /// <p>A unique identifier for the workflow.</p>
    pub fn get_workflow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workflow_id
    }
    /// Consumes the builder and constructs a [`DescribeWorkflowInput`](crate::operation::describe_workflow::DescribeWorkflowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_workflow::DescribeWorkflowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_workflow::DescribeWorkflowInput {
            workflow_id: self.workflow_id,
        })
    }
}
