// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyActivityStreamInput {
    /// <p>The Amazon Resource Name (ARN) of the RDS for Oracle or Microsoft SQL Server DB instance. For example, <code>arn:aws:rds:us-east-1:12345667890:db:my-orcl-db</code>.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The audit policy state. When a policy is unlocked, it is read/write. When it is locked, it is read-only. You can edit your audit policy only when the activity stream is unlocked or stopped.</p>
    pub audit_policy_state: ::std::option::Option<crate::types::AuditPolicyState>,
}
impl ModifyActivityStreamInput {
    /// <p>The Amazon Resource Name (ARN) of the RDS for Oracle or Microsoft SQL Server DB instance. For example, <code>arn:aws:rds:us-east-1:12345667890:db:my-orcl-db</code>.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The audit policy state. When a policy is unlocked, it is read/write. When it is locked, it is read-only. You can edit your audit policy only when the activity stream is unlocked or stopped.</p>
    pub fn audit_policy_state(&self) -> ::std::option::Option<&crate::types::AuditPolicyState> {
        self.audit_policy_state.as_ref()
    }
}
impl ModifyActivityStreamInput {
    /// Creates a new builder-style object to manufacture [`ModifyActivityStreamInput`](crate::operation::modify_activity_stream::ModifyActivityStreamInput).
    pub fn builder() -> crate::operation::modify_activity_stream::builders::ModifyActivityStreamInputBuilder {
        crate::operation::modify_activity_stream::builders::ModifyActivityStreamInputBuilder::default()
    }
}

/// A builder for [`ModifyActivityStreamInput`](crate::operation::modify_activity_stream::ModifyActivityStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyActivityStreamInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) audit_policy_state: ::std::option::Option<crate::types::AuditPolicyState>,
}
impl ModifyActivityStreamInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the RDS for Oracle or Microsoft SQL Server DB instance. For example, <code>arn:aws:rds:us-east-1:12345667890:db:my-orcl-db</code>.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS for Oracle or Microsoft SQL Server DB instance. For example, <code>arn:aws:rds:us-east-1:12345667890:db:my-orcl-db</code>.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the RDS for Oracle or Microsoft SQL Server DB instance. For example, <code>arn:aws:rds:us-east-1:12345667890:db:my-orcl-db</code>.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The audit policy state. When a policy is unlocked, it is read/write. When it is locked, it is read-only. You can edit your audit policy only when the activity stream is unlocked or stopped.</p>
    pub fn audit_policy_state(mut self, input: crate::types::AuditPolicyState) -> Self {
        self.audit_policy_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The audit policy state. When a policy is unlocked, it is read/write. When it is locked, it is read-only. You can edit your audit policy only when the activity stream is unlocked or stopped.</p>
    pub fn set_audit_policy_state(mut self, input: ::std::option::Option<crate::types::AuditPolicyState>) -> Self {
        self.audit_policy_state = input;
        self
    }
    /// <p>The audit policy state. When a policy is unlocked, it is read/write. When it is locked, it is read-only. You can edit your audit policy only when the activity stream is unlocked or stopped.</p>
    pub fn get_audit_policy_state(&self) -> &::std::option::Option<crate::types::AuditPolicyState> {
        &self.audit_policy_state
    }
    /// Consumes the builder and constructs a [`ModifyActivityStreamInput`](crate::operation::modify_activity_stream::ModifyActivityStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::modify_activity_stream::ModifyActivityStreamInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::modify_activity_stream::ModifyActivityStreamInput {
            resource_arn: self.resource_arn,
            audit_policy_state: self.audit_policy_state,
        })
    }
}
