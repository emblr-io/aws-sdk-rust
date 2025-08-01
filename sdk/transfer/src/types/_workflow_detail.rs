// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the workflow ID for the workflow to assign and the execution role that's used for executing the workflow.</p>
/// <p>In addition to a workflow to execute when a file is uploaded completely, <code>WorkflowDetails</code> can also contain a workflow ID (and execution role) for a workflow to execute on partial upload. A partial upload occurs when the server session disconnects while the file is still being uploaded.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowDetail {
    /// <p>A unique identifier for the workflow.</p>
    pub workflow_id: ::std::string::String,
    /// <p>Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources</p>
    pub execution_role: ::std::string::String,
}
impl WorkflowDetail {
    /// <p>A unique identifier for the workflow.</p>
    pub fn workflow_id(&self) -> &str {
        use std::ops::Deref;
        self.workflow_id.deref()
    }
    /// <p>Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources</p>
    pub fn execution_role(&self) -> &str {
        use std::ops::Deref;
        self.execution_role.deref()
    }
}
impl WorkflowDetail {
    /// Creates a new builder-style object to manufacture [`WorkflowDetail`](crate::types::WorkflowDetail).
    pub fn builder() -> crate::types::builders::WorkflowDetailBuilder {
        crate::types::builders::WorkflowDetailBuilder::default()
    }
}

/// A builder for [`WorkflowDetail`](crate::types::WorkflowDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowDetailBuilder {
    pub(crate) workflow_id: ::std::option::Option<::std::string::String>,
    pub(crate) execution_role: ::std::option::Option<::std::string::String>,
}
impl WorkflowDetailBuilder {
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
    /// <p>Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources</p>
    /// This field is required.
    pub fn execution_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources</p>
    pub fn set_execution_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role = input;
        self
    }
    /// <p>Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources</p>
    pub fn get_execution_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role
    }
    /// Consumes the builder and constructs a [`WorkflowDetail`](crate::types::WorkflowDetail).
    /// This method will fail if any of the following fields are not set:
    /// - [`workflow_id`](crate::types::builders::WorkflowDetailBuilder::workflow_id)
    /// - [`execution_role`](crate::types::builders::WorkflowDetailBuilder::execution_role)
    pub fn build(self) -> ::std::result::Result<crate::types::WorkflowDetail, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WorkflowDetail {
            workflow_id: self.workflow_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workflow_id",
                    "workflow_id was not specified but it is required when building WorkflowDetail",
                )
            })?,
            execution_role: self.execution_role.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_role",
                    "execution_role was not specified but it is required when building WorkflowDetail",
                )
            })?,
        })
    }
}
