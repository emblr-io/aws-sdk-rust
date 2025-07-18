// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAuditMitigationActionsTaskInput {
    /// <p>The unique identifier for the audit mitigation task.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAuditMitigationActionsTaskInput {
    /// <p>The unique identifier for the audit mitigation task.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
}
impl DescribeAuditMitigationActionsTaskInput {
    /// Creates a new builder-style object to manufacture [`DescribeAuditMitigationActionsTaskInput`](crate::operation::describe_audit_mitigation_actions_task::DescribeAuditMitigationActionsTaskInput).
    pub fn builder() -> crate::operation::describe_audit_mitigation_actions_task::builders::DescribeAuditMitigationActionsTaskInputBuilder {
        crate::operation::describe_audit_mitigation_actions_task::builders::DescribeAuditMitigationActionsTaskInputBuilder::default()
    }
}

/// A builder for [`DescribeAuditMitigationActionsTaskInput`](crate::operation::describe_audit_mitigation_actions_task::DescribeAuditMitigationActionsTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAuditMitigationActionsTaskInputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAuditMitigationActionsTaskInputBuilder {
    /// <p>The unique identifier for the audit mitigation task.</p>
    /// This field is required.
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the audit mitigation task.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The unique identifier for the audit mitigation task.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// Consumes the builder and constructs a [`DescribeAuditMitigationActionsTaskInput`](crate::operation::describe_audit_mitigation_actions_task::DescribeAuditMitigationActionsTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_audit_mitigation_actions_task::DescribeAuditMitigationActionsTaskInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_audit_mitigation_actions_task::DescribeAuditMitigationActionsTaskInput { task_id: self.task_id },
        )
    }
}
