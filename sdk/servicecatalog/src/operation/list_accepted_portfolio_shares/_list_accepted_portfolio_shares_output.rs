// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAcceptedPortfolioSharesOutput {
    /// <p>Information about the portfolios.</p>
    pub portfolio_details: ::std::option::Option<::std::vec::Vec<crate::types::PortfolioDetail>>,
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAcceptedPortfolioSharesOutput {
    /// <p>Information about the portfolios.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.portfolio_details.is_none()`.
    pub fn portfolio_details(&self) -> &[crate::types::PortfolioDetail] {
        self.portfolio_details.as_deref().unwrap_or_default()
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAcceptedPortfolioSharesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAcceptedPortfolioSharesOutput {
    /// Creates a new builder-style object to manufacture [`ListAcceptedPortfolioSharesOutput`](crate::operation::list_accepted_portfolio_shares::ListAcceptedPortfolioSharesOutput).
    pub fn builder() -> crate::operation::list_accepted_portfolio_shares::builders::ListAcceptedPortfolioSharesOutputBuilder {
        crate::operation::list_accepted_portfolio_shares::builders::ListAcceptedPortfolioSharesOutputBuilder::default()
    }
}

/// A builder for [`ListAcceptedPortfolioSharesOutput`](crate::operation::list_accepted_portfolio_shares::ListAcceptedPortfolioSharesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAcceptedPortfolioSharesOutputBuilder {
    pub(crate) portfolio_details: ::std::option::Option<::std::vec::Vec<crate::types::PortfolioDetail>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAcceptedPortfolioSharesOutputBuilder {
    /// Appends an item to `portfolio_details`.
    ///
    /// To override the contents of this collection use [`set_portfolio_details`](Self::set_portfolio_details).
    ///
    /// <p>Information about the portfolios.</p>
    pub fn portfolio_details(mut self, input: crate::types::PortfolioDetail) -> Self {
        let mut v = self.portfolio_details.unwrap_or_default();
        v.push(input);
        self.portfolio_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the portfolios.</p>
    pub fn set_portfolio_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PortfolioDetail>>) -> Self {
        self.portfolio_details = input;
        self
    }
    /// <p>Information about the portfolios.</p>
    pub fn get_portfolio_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PortfolioDetail>> {
        &self.portfolio_details
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListAcceptedPortfolioSharesOutput`](crate::operation::list_accepted_portfolio_shares::ListAcceptedPortfolioSharesOutput).
    pub fn build(self) -> crate::operation::list_accepted_portfolio_shares::ListAcceptedPortfolioSharesOutput {
        crate::operation::list_accepted_portfolio_shares::ListAcceptedPortfolioSharesOutput {
            portfolio_details: self.portfolio_details,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
