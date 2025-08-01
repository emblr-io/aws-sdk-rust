// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMembersOutput {
    /// <p>The list of Amazon Web Services accounts that were not processed. For each account, the list includes the account ID and the email address.</p>
    pub unprocessed_accounts: ::std::option::Option<::std::vec::Vec<crate::types::Result>>,
    _request_id: Option<String>,
}
impl CreateMembersOutput {
    /// <p>The list of Amazon Web Services accounts that were not processed. For each account, the list includes the account ID and the email address.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unprocessed_accounts.is_none()`.
    pub fn unprocessed_accounts(&self) -> &[crate::types::Result] {
        self.unprocessed_accounts.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateMembersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateMembersOutput {
    /// Creates a new builder-style object to manufacture [`CreateMembersOutput`](crate::operation::create_members::CreateMembersOutput).
    pub fn builder() -> crate::operation::create_members::builders::CreateMembersOutputBuilder {
        crate::operation::create_members::builders::CreateMembersOutputBuilder::default()
    }
}

/// A builder for [`CreateMembersOutput`](crate::operation::create_members::CreateMembersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMembersOutputBuilder {
    pub(crate) unprocessed_accounts: ::std::option::Option<::std::vec::Vec<crate::types::Result>>,
    _request_id: Option<String>,
}
impl CreateMembersOutputBuilder {
    /// Appends an item to `unprocessed_accounts`.
    ///
    /// To override the contents of this collection use [`set_unprocessed_accounts`](Self::set_unprocessed_accounts).
    ///
    /// <p>The list of Amazon Web Services accounts that were not processed. For each account, the list includes the account ID and the email address.</p>
    pub fn unprocessed_accounts(mut self, input: crate::types::Result) -> Self {
        let mut v = self.unprocessed_accounts.unwrap_or_default();
        v.push(input);
        self.unprocessed_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of Amazon Web Services accounts that were not processed. For each account, the list includes the account ID and the email address.</p>
    pub fn set_unprocessed_accounts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Result>>) -> Self {
        self.unprocessed_accounts = input;
        self
    }
    /// <p>The list of Amazon Web Services accounts that were not processed. For each account, the list includes the account ID and the email address.</p>
    pub fn get_unprocessed_accounts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Result>> {
        &self.unprocessed_accounts
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateMembersOutput`](crate::operation::create_members::CreateMembersOutput).
    pub fn build(self) -> crate::operation::create_members::CreateMembersOutput {
        crate::operation::create_members::CreateMembersOutput {
            unprocessed_accounts: self.unprocessed_accounts,
            _request_id: self._request_id,
        }
    }
}
