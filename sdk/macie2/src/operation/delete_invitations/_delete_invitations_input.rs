// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInvitationsInput {
    /// <p>An array that lists Amazon Web Services account IDs, one for each account that sent an invitation to delete.</p>
    pub account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteInvitationsInput {
    /// <p>An array that lists Amazon Web Services account IDs, one for each account that sent an invitation to delete.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_ids.is_none()`.
    pub fn account_ids(&self) -> &[::std::string::String] {
        self.account_ids.as_deref().unwrap_or_default()
    }
}
impl DeleteInvitationsInput {
    /// Creates a new builder-style object to manufacture [`DeleteInvitationsInput`](crate::operation::delete_invitations::DeleteInvitationsInput).
    pub fn builder() -> crate::operation::delete_invitations::builders::DeleteInvitationsInputBuilder {
        crate::operation::delete_invitations::builders::DeleteInvitationsInputBuilder::default()
    }
}

/// A builder for [`DeleteInvitationsInput`](crate::operation::delete_invitations::DeleteInvitationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInvitationsInputBuilder {
    pub(crate) account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteInvitationsInputBuilder {
    /// Appends an item to `account_ids`.
    ///
    /// To override the contents of this collection use [`set_account_ids`](Self::set_account_ids).
    ///
    /// <p>An array that lists Amazon Web Services account IDs, one for each account that sent an invitation to delete.</p>
    pub fn account_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_ids.unwrap_or_default();
        v.push(input.into());
        self.account_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that lists Amazon Web Services account IDs, one for each account that sent an invitation to delete.</p>
    pub fn set_account_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_ids = input;
        self
    }
    /// <p>An array that lists Amazon Web Services account IDs, one for each account that sent an invitation to delete.</p>
    pub fn get_account_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_ids
    }
    /// Consumes the builder and constructs a [`DeleteInvitationsInput`](crate::operation::delete_invitations::DeleteInvitationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_invitations::DeleteInvitationsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_invitations::DeleteInvitationsInput {
            account_ids: self.account_ids,
        })
    }
}
