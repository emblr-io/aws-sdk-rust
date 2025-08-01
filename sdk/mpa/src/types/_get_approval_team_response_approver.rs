// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details for an approver.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApprovalTeamResponseApprover {
    /// <p>ID for the approver.</p>
    pub approver_id: ::std::option::Option<::std::string::String>,
    /// <p>Timestamp when the approver responded to an approval team invitation.</p>
    pub response_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>ID for the user.</p>
    pub primary_identity_id: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) for the identity source. The identity source manages the user authentication for approvers.</p>
    pub primary_identity_source_arn: ::std::option::Option<::std::string::String>,
    /// <p>Status for the identity source. For example, if an approver has accepted a team invitation with a user authentication method managed by the identity source.</p>
    pub primary_identity_status: ::std::option::Option<crate::types::IdentityStatus>,
}
impl GetApprovalTeamResponseApprover {
    /// <p>ID for the approver.</p>
    pub fn approver_id(&self) -> ::std::option::Option<&str> {
        self.approver_id.as_deref()
    }
    /// <p>Timestamp when the approver responded to an approval team invitation.</p>
    pub fn response_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.response_time.as_ref()
    }
    /// <p>ID for the user.</p>
    pub fn primary_identity_id(&self) -> ::std::option::Option<&str> {
        self.primary_identity_id.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) for the identity source. The identity source manages the user authentication for approvers.</p>
    pub fn primary_identity_source_arn(&self) -> ::std::option::Option<&str> {
        self.primary_identity_source_arn.as_deref()
    }
    /// <p>Status for the identity source. For example, if an approver has accepted a team invitation with a user authentication method managed by the identity source.</p>
    pub fn primary_identity_status(&self) -> ::std::option::Option<&crate::types::IdentityStatus> {
        self.primary_identity_status.as_ref()
    }
}
impl GetApprovalTeamResponseApprover {
    /// Creates a new builder-style object to manufacture [`GetApprovalTeamResponseApprover`](crate::types::GetApprovalTeamResponseApprover).
    pub fn builder() -> crate::types::builders::GetApprovalTeamResponseApproverBuilder {
        crate::types::builders::GetApprovalTeamResponseApproverBuilder::default()
    }
}

/// A builder for [`GetApprovalTeamResponseApprover`](crate::types::GetApprovalTeamResponseApprover).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApprovalTeamResponseApproverBuilder {
    pub(crate) approver_id: ::std::option::Option<::std::string::String>,
    pub(crate) response_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) primary_identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) primary_identity_source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) primary_identity_status: ::std::option::Option<crate::types::IdentityStatus>,
}
impl GetApprovalTeamResponseApproverBuilder {
    /// <p>ID for the approver.</p>
    pub fn approver_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.approver_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID for the approver.</p>
    pub fn set_approver_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.approver_id = input;
        self
    }
    /// <p>ID for the approver.</p>
    pub fn get_approver_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.approver_id
    }
    /// <p>Timestamp when the approver responded to an approval team invitation.</p>
    pub fn response_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.response_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Timestamp when the approver responded to an approval team invitation.</p>
    pub fn set_response_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.response_time = input;
        self
    }
    /// <p>Timestamp when the approver responded to an approval team invitation.</p>
    pub fn get_response_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.response_time
    }
    /// <p>ID for the user.</p>
    pub fn primary_identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID for the user.</p>
    pub fn set_primary_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_identity_id = input;
        self
    }
    /// <p>ID for the user.</p>
    pub fn get_primary_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_identity_id
    }
    /// <p>Amazon Resource Name (ARN) for the identity source. The identity source manages the user authentication for approvers.</p>
    pub fn primary_identity_source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_identity_source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) for the identity source. The identity source manages the user authentication for approvers.</p>
    pub fn set_primary_identity_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_identity_source_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) for the identity source. The identity source manages the user authentication for approvers.</p>
    pub fn get_primary_identity_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_identity_source_arn
    }
    /// <p>Status for the identity source. For example, if an approver has accepted a team invitation with a user authentication method managed by the identity source.</p>
    pub fn primary_identity_status(mut self, input: crate::types::IdentityStatus) -> Self {
        self.primary_identity_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status for the identity source. For example, if an approver has accepted a team invitation with a user authentication method managed by the identity source.</p>
    pub fn set_primary_identity_status(mut self, input: ::std::option::Option<crate::types::IdentityStatus>) -> Self {
        self.primary_identity_status = input;
        self
    }
    /// <p>Status for the identity source. For example, if an approver has accepted a team invitation with a user authentication method managed by the identity source.</p>
    pub fn get_primary_identity_status(&self) -> &::std::option::Option<crate::types::IdentityStatus> {
        &self.primary_identity_status
    }
    /// Consumes the builder and constructs a [`GetApprovalTeamResponseApprover`](crate::types::GetApprovalTeamResponseApprover).
    pub fn build(self) -> crate::types::GetApprovalTeamResponseApprover {
        crate::types::GetApprovalTeamResponseApprover {
            approver_id: self.approver_id,
            response_time: self.response_time,
            primary_identity_id: self.primary_identity_id,
            primary_identity_source_arn: self.primary_identity_source_arn,
            primary_identity_status: self.primary_identity_status,
        }
    }
}
