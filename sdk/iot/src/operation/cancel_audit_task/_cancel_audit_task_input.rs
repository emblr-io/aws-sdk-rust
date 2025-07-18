// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelAuditTaskInput {
    /// <p>The ID of the audit you want to cancel. You can only cancel an audit that is "IN_PROGRESS".</p>
    pub task_id: ::std::option::Option<::std::string::String>,
}
impl CancelAuditTaskInput {
    /// <p>The ID of the audit you want to cancel. You can only cancel an audit that is "IN_PROGRESS".</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
}
impl CancelAuditTaskInput {
    /// Creates a new builder-style object to manufacture [`CancelAuditTaskInput`](crate::operation::cancel_audit_task::CancelAuditTaskInput).
    pub fn builder() -> crate::operation::cancel_audit_task::builders::CancelAuditTaskInputBuilder {
        crate::operation::cancel_audit_task::builders::CancelAuditTaskInputBuilder::default()
    }
}

/// A builder for [`CancelAuditTaskInput`](crate::operation::cancel_audit_task::CancelAuditTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelAuditTaskInputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
}
impl CancelAuditTaskInputBuilder {
    /// <p>The ID of the audit you want to cancel. You can only cancel an audit that is "IN_PROGRESS".</p>
    /// This field is required.
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the audit you want to cancel. You can only cancel an audit that is "IN_PROGRESS".</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The ID of the audit you want to cancel. You can only cancel an audit that is "IN_PROGRESS".</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// Consumes the builder and constructs a [`CancelAuditTaskInput`](crate::operation::cancel_audit_task::CancelAuditTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_audit_task::CancelAuditTaskInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_audit_task::CancelAuditTaskInput { task_id: self.task_id })
    }
}
