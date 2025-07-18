// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AcceptInvitationInput {
    /// <p>The Amazon Web Services account ID for the account that sent the invitation.</p>
    pub administrator_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the invitation to accept.</p>
    pub invitation_id: ::std::option::Option<::std::string::String>,
    /// <p>(Deprecated) The Amazon Web Services account ID for the account that sent the invitation. This property has been replaced by the administratorAccountId property and is retained only for backward compatibility.</p>
    pub master_account: ::std::option::Option<::std::string::String>,
}
impl AcceptInvitationInput {
    /// <p>The Amazon Web Services account ID for the account that sent the invitation.</p>
    pub fn administrator_account_id(&self) -> ::std::option::Option<&str> {
        self.administrator_account_id.as_deref()
    }
    /// <p>The unique identifier for the invitation to accept.</p>
    pub fn invitation_id(&self) -> ::std::option::Option<&str> {
        self.invitation_id.as_deref()
    }
    /// <p>(Deprecated) The Amazon Web Services account ID for the account that sent the invitation. This property has been replaced by the administratorAccountId property and is retained only for backward compatibility.</p>
    pub fn master_account(&self) -> ::std::option::Option<&str> {
        self.master_account.as_deref()
    }
}
impl AcceptInvitationInput {
    /// Creates a new builder-style object to manufacture [`AcceptInvitationInput`](crate::operation::accept_invitation::AcceptInvitationInput).
    pub fn builder() -> crate::operation::accept_invitation::builders::AcceptInvitationInputBuilder {
        crate::operation::accept_invitation::builders::AcceptInvitationInputBuilder::default()
    }
}

/// A builder for [`AcceptInvitationInput`](crate::operation::accept_invitation::AcceptInvitationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AcceptInvitationInputBuilder {
    pub(crate) administrator_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) invitation_id: ::std::option::Option<::std::string::String>,
    pub(crate) master_account: ::std::option::Option<::std::string::String>,
}
impl AcceptInvitationInputBuilder {
    /// <p>The Amazon Web Services account ID for the account that sent the invitation.</p>
    pub fn administrator_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.administrator_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID for the account that sent the invitation.</p>
    pub fn set_administrator_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.administrator_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID for the account that sent the invitation.</p>
    pub fn get_administrator_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.administrator_account_id
    }
    /// <p>The unique identifier for the invitation to accept.</p>
    /// This field is required.
    pub fn invitation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invitation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the invitation to accept.</p>
    pub fn set_invitation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invitation_id = input;
        self
    }
    /// <p>The unique identifier for the invitation to accept.</p>
    pub fn get_invitation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invitation_id
    }
    /// <p>(Deprecated) The Amazon Web Services account ID for the account that sent the invitation. This property has been replaced by the administratorAccountId property and is retained only for backward compatibility.</p>
    pub fn master_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Deprecated) The Amazon Web Services account ID for the account that sent the invitation. This property has been replaced by the administratorAccountId property and is retained only for backward compatibility.</p>
    pub fn set_master_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_account = input;
        self
    }
    /// <p>(Deprecated) The Amazon Web Services account ID for the account that sent the invitation. This property has been replaced by the administratorAccountId property and is retained only for backward compatibility.</p>
    pub fn get_master_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_account
    }
    /// Consumes the builder and constructs a [`AcceptInvitationInput`](crate::operation::accept_invitation::AcceptInvitationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::accept_invitation::AcceptInvitationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::accept_invitation::AcceptInvitationInput {
            administrator_account_id: self.administrator_account_id,
            invitation_id: self.invitation_id,
            master_account: self.master_account,
        })
    }
}
