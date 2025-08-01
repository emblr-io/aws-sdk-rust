// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPrincipalsForPortfolioOutput {
    /// <p>The <code>PrincipalARN</code>s and corresponding <code>PrincipalType</code>s associated with the portfolio.</p>
    pub principals: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>,
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPrincipalsForPortfolioOutput {
    /// <p>The <code>PrincipalARN</code>s and corresponding <code>PrincipalType</code>s associated with the portfolio.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.principals.is_none()`.
    pub fn principals(&self) -> &[crate::types::Principal] {
        self.principals.as_deref().unwrap_or_default()
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPrincipalsForPortfolioOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPrincipalsForPortfolioOutput {
    /// Creates a new builder-style object to manufacture [`ListPrincipalsForPortfolioOutput`](crate::operation::list_principals_for_portfolio::ListPrincipalsForPortfolioOutput).
    pub fn builder() -> crate::operation::list_principals_for_portfolio::builders::ListPrincipalsForPortfolioOutputBuilder {
        crate::operation::list_principals_for_portfolio::builders::ListPrincipalsForPortfolioOutputBuilder::default()
    }
}

/// A builder for [`ListPrincipalsForPortfolioOutput`](crate::operation::list_principals_for_portfolio::ListPrincipalsForPortfolioOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPrincipalsForPortfolioOutputBuilder {
    pub(crate) principals: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPrincipalsForPortfolioOutputBuilder {
    /// Appends an item to `principals`.
    ///
    /// To override the contents of this collection use [`set_principals`](Self::set_principals).
    ///
    /// <p>The <code>PrincipalARN</code>s and corresponding <code>PrincipalType</code>s associated with the portfolio.</p>
    pub fn principals(mut self, input: crate::types::Principal) -> Self {
        let mut v = self.principals.unwrap_or_default();
        v.push(input);
        self.principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <code>PrincipalARN</code>s and corresponding <code>PrincipalType</code>s associated with the portfolio.</p>
    pub fn set_principals(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>) -> Self {
        self.principals = input;
        self
    }
    /// <p>The <code>PrincipalARN</code>s and corresponding <code>PrincipalType</code>s associated with the portfolio.</p>
    pub fn get_principals(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Principal>> {
        &self.principals
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
    /// Consumes the builder and constructs a [`ListPrincipalsForPortfolioOutput`](crate::operation::list_principals_for_portfolio::ListPrincipalsForPortfolioOutput).
    pub fn build(self) -> crate::operation::list_principals_for_portfolio::ListPrincipalsForPortfolioOutput {
        crate::operation::list_principals_for_portfolio::ListPrincipalsForPortfolioOutput {
            principals: self.principals,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
