// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPartnerAccountsOutput {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Sidewalk account credentials.</p>
    pub sidewalk: ::std::option::Option<::std::vec::Vec<crate::types::SidewalkAccountInfoWithFingerprint>>,
    _request_id: Option<String>,
}
impl ListPartnerAccountsOutput {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Sidewalk account credentials.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sidewalk.is_none()`.
    pub fn sidewalk(&self) -> &[crate::types::SidewalkAccountInfoWithFingerprint] {
        self.sidewalk.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListPartnerAccountsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPartnerAccountsOutput {
    /// Creates a new builder-style object to manufacture [`ListPartnerAccountsOutput`](crate::operation::list_partner_accounts::ListPartnerAccountsOutput).
    pub fn builder() -> crate::operation::list_partner_accounts::builders::ListPartnerAccountsOutputBuilder {
        crate::operation::list_partner_accounts::builders::ListPartnerAccountsOutputBuilder::default()
    }
}

/// A builder for [`ListPartnerAccountsOutput`](crate::operation::list_partner_accounts::ListPartnerAccountsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPartnerAccountsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sidewalk: ::std::option::Option<::std::vec::Vec<crate::types::SidewalkAccountInfoWithFingerprint>>,
    _request_id: Option<String>,
}
impl ListPartnerAccountsOutputBuilder {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `sidewalk`.
    ///
    /// To override the contents of this collection use [`set_sidewalk`](Self::set_sidewalk).
    ///
    /// <p>The Sidewalk account credentials.</p>
    pub fn sidewalk(mut self, input: crate::types::SidewalkAccountInfoWithFingerprint) -> Self {
        let mut v = self.sidewalk.unwrap_or_default();
        v.push(input);
        self.sidewalk = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Sidewalk account credentials.</p>
    pub fn set_sidewalk(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SidewalkAccountInfoWithFingerprint>>) -> Self {
        self.sidewalk = input;
        self
    }
    /// <p>The Sidewalk account credentials.</p>
    pub fn get_sidewalk(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SidewalkAccountInfoWithFingerprint>> {
        &self.sidewalk
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPartnerAccountsOutput`](crate::operation::list_partner_accounts::ListPartnerAccountsOutput).
    pub fn build(self) -> crate::operation::list_partner_accounts::ListPartnerAccountsOutput {
        crate::operation::list_partner_accounts::ListPartnerAccountsOutput {
            next_token: self.next_token,
            sidewalk: self.sidewalk,
            _request_id: self._request_id,
        }
    }
}
