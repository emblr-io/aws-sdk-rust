// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMembersInput {
    /// <p>The list of accounts to associate with the Security Hub administrator account. For each account, the list includes the account ID and optionally the email address.</p>
    pub account_details: ::std::option::Option<::std::vec::Vec<crate::types::AccountDetails>>,
}
impl CreateMembersInput {
    /// <p>The list of accounts to associate with the Security Hub administrator account. For each account, the list includes the account ID and optionally the email address.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_details.is_none()`.
    pub fn account_details(&self) -> &[crate::types::AccountDetails] {
        self.account_details.as_deref().unwrap_or_default()
    }
}
impl CreateMembersInput {
    /// Creates a new builder-style object to manufacture [`CreateMembersInput`](crate::operation::create_members::CreateMembersInput).
    pub fn builder() -> crate::operation::create_members::builders::CreateMembersInputBuilder {
        crate::operation::create_members::builders::CreateMembersInputBuilder::default()
    }
}

/// A builder for [`CreateMembersInput`](crate::operation::create_members::CreateMembersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMembersInputBuilder {
    pub(crate) account_details: ::std::option::Option<::std::vec::Vec<crate::types::AccountDetails>>,
}
impl CreateMembersInputBuilder {
    /// Appends an item to `account_details`.
    ///
    /// To override the contents of this collection use [`set_account_details`](Self::set_account_details).
    ///
    /// <p>The list of accounts to associate with the Security Hub administrator account. For each account, the list includes the account ID and optionally the email address.</p>
    pub fn account_details(mut self, input: crate::types::AccountDetails) -> Self {
        let mut v = self.account_details.unwrap_or_default();
        v.push(input);
        self.account_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of accounts to associate with the Security Hub administrator account. For each account, the list includes the account ID and optionally the email address.</p>
    pub fn set_account_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AccountDetails>>) -> Self {
        self.account_details = input;
        self
    }
    /// <p>The list of accounts to associate with the Security Hub administrator account. For each account, the list includes the account ID and optionally the email address.</p>
    pub fn get_account_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AccountDetails>> {
        &self.account_details
    }
    /// Consumes the builder and constructs a [`CreateMembersInput`](crate::operation::create_members::CreateMembersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_members::CreateMembersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_members::CreateMembersInput {
            account_details: self.account_details,
        })
    }
}
