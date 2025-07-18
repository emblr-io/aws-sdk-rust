// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns information about a specific approval on a pull request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Approval {
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the approval, APPROVE or REVOKE. REVOKE states are not stored.</p>
    pub approval_state: ::std::option::Option<crate::types::ApprovalState>,
}
impl Approval {
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn user_arn(&self) -> ::std::option::Option<&str> {
        self.user_arn.as_deref()
    }
    /// <p>The state of the approval, APPROVE or REVOKE. REVOKE states are not stored.</p>
    pub fn approval_state(&self) -> ::std::option::Option<&crate::types::ApprovalState> {
        self.approval_state.as_ref()
    }
}
impl Approval {
    /// Creates a new builder-style object to manufacture [`Approval`](crate::types::Approval).
    pub fn builder() -> crate::types::builders::ApprovalBuilder {
        crate::types::builders::ApprovalBuilder::default()
    }
}

/// A builder for [`Approval`](crate::types::Approval).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApprovalBuilder {
    pub(crate) user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) approval_state: ::std::option::Option<crate::types::ApprovalState>,
}
impl ApprovalBuilder {
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn set_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn get_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_arn
    }
    /// <p>The state of the approval, APPROVE or REVOKE. REVOKE states are not stored.</p>
    pub fn approval_state(mut self, input: crate::types::ApprovalState) -> Self {
        self.approval_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the approval, APPROVE or REVOKE. REVOKE states are not stored.</p>
    pub fn set_approval_state(mut self, input: ::std::option::Option<crate::types::ApprovalState>) -> Self {
        self.approval_state = input;
        self
    }
    /// <p>The state of the approval, APPROVE or REVOKE. REVOKE states are not stored.</p>
    pub fn get_approval_state(&self) -> &::std::option::Option<crate::types::ApprovalState> {
        &self.approval_state
    }
    /// Consumes the builder and constructs a [`Approval`](crate::types::Approval).
    pub fn build(self) -> crate::types::Approval {
        crate::types::Approval {
            user_arn: self.user_arn,
            approval_state: self.approval_state,
        }
    }
}
