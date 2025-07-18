// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an invitation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Invitation {
    /// <p>The account ID of the Security Hub administrator account that the invitation was sent from.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the invitation sent to the member account.</p>
    pub invitation_id: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the invitation was sent.</p>
    pub invited_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current status of the association between the member and administrator accounts.</p>
    pub member_status: ::std::option::Option<::std::string::String>,
}
impl Invitation {
    /// <p>The account ID of the Security Hub administrator account that the invitation was sent from.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The ID of the invitation sent to the member account.</p>
    pub fn invitation_id(&self) -> ::std::option::Option<&str> {
        self.invitation_id.as_deref()
    }
    /// <p>The timestamp of when the invitation was sent.</p>
    pub fn invited_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.invited_at.as_ref()
    }
    /// <p>The current status of the association between the member and administrator accounts.</p>
    pub fn member_status(&self) -> ::std::option::Option<&str> {
        self.member_status.as_deref()
    }
}
impl Invitation {
    /// Creates a new builder-style object to manufacture [`Invitation`](crate::types::Invitation).
    pub fn builder() -> crate::types::builders::InvitationBuilder {
        crate::types::builders::InvitationBuilder::default()
    }
}

/// A builder for [`Invitation`](crate::types::Invitation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvitationBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) invitation_id: ::std::option::Option<::std::string::String>,
    pub(crate) invited_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) member_status: ::std::option::Option<::std::string::String>,
}
impl InvitationBuilder {
    /// <p>The account ID of the Security Hub administrator account that the invitation was sent from.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the Security Hub administrator account that the invitation was sent from.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The account ID of the Security Hub administrator account that the invitation was sent from.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The ID of the invitation sent to the member account.</p>
    pub fn invitation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invitation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the invitation sent to the member account.</p>
    pub fn set_invitation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invitation_id = input;
        self
    }
    /// <p>The ID of the invitation sent to the member account.</p>
    pub fn get_invitation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invitation_id
    }
    /// <p>The timestamp of when the invitation was sent.</p>
    pub fn invited_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.invited_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the invitation was sent.</p>
    pub fn set_invited_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.invited_at = input;
        self
    }
    /// <p>The timestamp of when the invitation was sent.</p>
    pub fn get_invited_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.invited_at
    }
    /// <p>The current status of the association between the member and administrator accounts.</p>
    pub fn member_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.member_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current status of the association between the member and administrator accounts.</p>
    pub fn set_member_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.member_status = input;
        self
    }
    /// <p>The current status of the association between the member and administrator accounts.</p>
    pub fn get_member_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.member_status
    }
    /// Consumes the builder and constructs a [`Invitation`](crate::types::Invitation).
    pub fn build(self) -> crate::types::Invitation {
        crate::types::Invitation {
            account_id: self.account_id,
            invitation_id: self.invitation_id,
            invited_at: self.invited_at,
            member_status: self.member_status,
        }
    }
}
