// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPartnerEventSourceAccountsOutput {
    /// <p>The list of partner event sources returned by the operation.</p>
    pub partner_event_source_accounts: ::std::option::Option<::std::vec::Vec<crate::types::PartnerEventSourceAccount>>,
    /// <p>A token indicating there are more results available. If there are no more results, no token is included in the response.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPartnerEventSourceAccountsOutput {
    /// <p>The list of partner event sources returned by the operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.partner_event_source_accounts.is_none()`.
    pub fn partner_event_source_accounts(&self) -> &[crate::types::PartnerEventSourceAccount] {
        self.partner_event_source_accounts.as_deref().unwrap_or_default()
    }
    /// <p>A token indicating there are more results available. If there are no more results, no token is included in the response.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPartnerEventSourceAccountsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPartnerEventSourceAccountsOutput {
    /// Creates a new builder-style object to manufacture [`ListPartnerEventSourceAccountsOutput`](crate::operation::list_partner_event_source_accounts::ListPartnerEventSourceAccountsOutput).
    pub fn builder() -> crate::operation::list_partner_event_source_accounts::builders::ListPartnerEventSourceAccountsOutputBuilder {
        crate::operation::list_partner_event_source_accounts::builders::ListPartnerEventSourceAccountsOutputBuilder::default()
    }
}

/// A builder for [`ListPartnerEventSourceAccountsOutput`](crate::operation::list_partner_event_source_accounts::ListPartnerEventSourceAccountsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPartnerEventSourceAccountsOutputBuilder {
    pub(crate) partner_event_source_accounts: ::std::option::Option<::std::vec::Vec<crate::types::PartnerEventSourceAccount>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPartnerEventSourceAccountsOutputBuilder {
    /// Appends an item to `partner_event_source_accounts`.
    ///
    /// To override the contents of this collection use [`set_partner_event_source_accounts`](Self::set_partner_event_source_accounts).
    ///
    /// <p>The list of partner event sources returned by the operation.</p>
    pub fn partner_event_source_accounts(mut self, input: crate::types::PartnerEventSourceAccount) -> Self {
        let mut v = self.partner_event_source_accounts.unwrap_or_default();
        v.push(input);
        self.partner_event_source_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of partner event sources returned by the operation.</p>
    pub fn set_partner_event_source_accounts(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::PartnerEventSourceAccount>>,
    ) -> Self {
        self.partner_event_source_accounts = input;
        self
    }
    /// <p>The list of partner event sources returned by the operation.</p>
    pub fn get_partner_event_source_accounts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PartnerEventSourceAccount>> {
        &self.partner_event_source_accounts
    }
    /// <p>A token indicating there are more results available. If there are no more results, no token is included in the response.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token indicating there are more results available. If there are no more results, no token is included in the response.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token indicating there are more results available. If there are no more results, no token is included in the response.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPartnerEventSourceAccountsOutput`](crate::operation::list_partner_event_source_accounts::ListPartnerEventSourceAccountsOutput).
    pub fn build(self) -> crate::operation::list_partner_event_source_accounts::ListPartnerEventSourceAccountsOutput {
        crate::operation::list_partner_event_source_accounts::ListPartnerEventSourceAccountsOutput {
            partner_event_source_accounts: self.partner_event_source_accounts,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
