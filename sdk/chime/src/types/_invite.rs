// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Invitation object returned after emailing users to invite them to join the Amazon Chime <code>Team</code> account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Invite {
    /// <p>The invite ID.</p>
    pub invite_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the invite.</p>
    pub status: ::std::option::Option<crate::types::InviteStatus>,
    /// <p>The email address to which the invite is sent.</p>
    pub email_address: ::std::option::Option<::std::string::String>,
    /// <p>The status of the invite email.</p>
    pub email_status: ::std::option::Option<crate::types::EmailStatus>,
}
impl Invite {
    /// <p>The invite ID.</p>
    pub fn invite_id(&self) -> ::std::option::Option<&str> {
        self.invite_id.as_deref()
    }
    /// <p>The status of the invite.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::InviteStatus> {
        self.status.as_ref()
    }
    /// <p>The email address to which the invite is sent.</p>
    pub fn email_address(&self) -> ::std::option::Option<&str> {
        self.email_address.as_deref()
    }
    /// <p>The status of the invite email.</p>
    pub fn email_status(&self) -> ::std::option::Option<&crate::types::EmailStatus> {
        self.email_status.as_ref()
    }
}
impl ::std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Invite");
        formatter.field("invite_id", &self.invite_id);
        formatter.field("status", &self.status);
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("email_status", &self.email_status);
        formatter.finish()
    }
}
impl Invite {
    /// Creates a new builder-style object to manufacture [`Invite`](crate::types::Invite).
    pub fn builder() -> crate::types::builders::InviteBuilder {
        crate::types::builders::InviteBuilder::default()
    }
}

/// A builder for [`Invite`](crate::types::Invite).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InviteBuilder {
    pub(crate) invite_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::InviteStatus>,
    pub(crate) email_address: ::std::option::Option<::std::string::String>,
    pub(crate) email_status: ::std::option::Option<crate::types::EmailStatus>,
}
impl InviteBuilder {
    /// <p>The invite ID.</p>
    pub fn invite_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invite_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The invite ID.</p>
    pub fn set_invite_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invite_id = input;
        self
    }
    /// <p>The invite ID.</p>
    pub fn get_invite_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invite_id
    }
    /// <p>The status of the invite.</p>
    pub fn status(mut self, input: crate::types::InviteStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the invite.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::InviteStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the invite.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::InviteStatus> {
        &self.status
    }
    /// <p>The email address to which the invite is sent.</p>
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address to which the invite is sent.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address = input;
        self
    }
    /// <p>The email address to which the invite is sent.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address
    }
    /// <p>The status of the invite email.</p>
    pub fn email_status(mut self, input: crate::types::EmailStatus) -> Self {
        self.email_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the invite email.</p>
    pub fn set_email_status(mut self, input: ::std::option::Option<crate::types::EmailStatus>) -> Self {
        self.email_status = input;
        self
    }
    /// <p>The status of the invite email.</p>
    pub fn get_email_status(&self) -> &::std::option::Option<crate::types::EmailStatus> {
        &self.email_status
    }
    /// Consumes the builder and constructs a [`Invite`](crate::types::Invite).
    pub fn build(self) -> crate::types::Invite {
        crate::types::Invite {
            invite_id: self.invite_id,
            status: self.status,
            email_address: self.email_address,
            email_status: self.email_status,
        }
    }
}
impl ::std::fmt::Debug for InviteBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InviteBuilder");
        formatter.field("invite_id", &self.invite_id);
        formatter.field("status", &self.status);
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("email_status", &self.email_status);
        formatter.finish()
    }
}
