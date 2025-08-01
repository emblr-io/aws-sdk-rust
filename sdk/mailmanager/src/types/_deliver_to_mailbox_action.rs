// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This action to delivers an email to a mailbox.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeliverToMailboxAction {
    /// <p>A policy that states what to do in the case of failure. The action will fail if there are configuration errors. For example, the mailbox ARN is no longer valid.</p>
    pub action_failure_policy: ::std::option::Option<crate::types::ActionFailurePolicy>,
    /// <p>The Amazon Resource Name (ARN) of a WorkMail organization to deliver the email to.</p>
    pub mailbox_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of an IAM role to use to execute this action. The role must have access to the workmail:DeliverToMailbox API.</p>
    pub role_arn: ::std::string::String,
}
impl DeliverToMailboxAction {
    /// <p>A policy that states what to do in the case of failure. The action will fail if there are configuration errors. For example, the mailbox ARN is no longer valid.</p>
    pub fn action_failure_policy(&self) -> ::std::option::Option<&crate::types::ActionFailurePolicy> {
        self.action_failure_policy.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of a WorkMail organization to deliver the email to.</p>
    pub fn mailbox_arn(&self) -> &str {
        use std::ops::Deref;
        self.mailbox_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role to use to execute this action. The role must have access to the workmail:DeliverToMailbox API.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
}
impl DeliverToMailboxAction {
    /// Creates a new builder-style object to manufacture [`DeliverToMailboxAction`](crate::types::DeliverToMailboxAction).
    pub fn builder() -> crate::types::builders::DeliverToMailboxActionBuilder {
        crate::types::builders::DeliverToMailboxActionBuilder::default()
    }
}

/// A builder for [`DeliverToMailboxAction`](crate::types::DeliverToMailboxAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeliverToMailboxActionBuilder {
    pub(crate) action_failure_policy: ::std::option::Option<crate::types::ActionFailurePolicy>,
    pub(crate) mailbox_arn: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl DeliverToMailboxActionBuilder {
    /// <p>A policy that states what to do in the case of failure. The action will fail if there are configuration errors. For example, the mailbox ARN is no longer valid.</p>
    pub fn action_failure_policy(mut self, input: crate::types::ActionFailurePolicy) -> Self {
        self.action_failure_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>A policy that states what to do in the case of failure. The action will fail if there are configuration errors. For example, the mailbox ARN is no longer valid.</p>
    pub fn set_action_failure_policy(mut self, input: ::std::option::Option<crate::types::ActionFailurePolicy>) -> Self {
        self.action_failure_policy = input;
        self
    }
    /// <p>A policy that states what to do in the case of failure. The action will fail if there are configuration errors. For example, the mailbox ARN is no longer valid.</p>
    pub fn get_action_failure_policy(&self) -> &::std::option::Option<crate::types::ActionFailurePolicy> {
        &self.action_failure_policy
    }
    /// <p>The Amazon Resource Name (ARN) of a WorkMail organization to deliver the email to.</p>
    /// This field is required.
    pub fn mailbox_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mailbox_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a WorkMail organization to deliver the email to.</p>
    pub fn set_mailbox_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mailbox_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a WorkMail organization to deliver the email to.</p>
    pub fn get_mailbox_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.mailbox_arn
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role to use to execute this action. The role must have access to the workmail:DeliverToMailbox API.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role to use to execute this action. The role must have access to the workmail:DeliverToMailbox API.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role to use to execute this action. The role must have access to the workmail:DeliverToMailbox API.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`DeliverToMailboxAction`](crate::types::DeliverToMailboxAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`mailbox_arn`](crate::types::builders::DeliverToMailboxActionBuilder::mailbox_arn)
    /// - [`role_arn`](crate::types::builders::DeliverToMailboxActionBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::DeliverToMailboxAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeliverToMailboxAction {
            action_failure_policy: self.action_failure_policy,
            mailbox_arn: self.mailbox_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mailbox_arn",
                    "mailbox_arn was not specified but it is required when building DeliverToMailboxAction",
                )
            })?,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building DeliverToMailboxAction",
                )
            })?,
        })
    }
}
