// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListWatchlistsInput {
    /// <p>The identifier of the domain.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that are returned per call. You can use <code>NextToken</code> to obtain more pages of results. The default is 100; the maximum allowed page size is also 100.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If <code>NextToken</code> is returned, there are more results available. The value of <code>NextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListWatchlistsInput {
    /// <p>The identifier of the domain.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>NextToken</code> to obtain more pages of results. The default is 100; the maximum allowed page size is also 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If <code>NextToken</code> is returned, there are more results available. The value of <code>NextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListWatchlistsInput {
    /// Creates a new builder-style object to manufacture [`ListWatchlistsInput`](crate::operation::list_watchlists::ListWatchlistsInput).
    pub fn builder() -> crate::operation::list_watchlists::builders::ListWatchlistsInputBuilder {
        crate::operation::list_watchlists::builders::ListWatchlistsInputBuilder::default()
    }
}

/// A builder for [`ListWatchlistsInput`](crate::operation::list_watchlists::ListWatchlistsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListWatchlistsInputBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListWatchlistsInputBuilder {
    /// <p>The identifier of the domain.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the domain.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the domain.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>NextToken</code> to obtain more pages of results. The default is 100; the maximum allowed page size is also 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>NextToken</code> to obtain more pages of results. The default is 100; the maximum allowed page size is also 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>NextToken</code> to obtain more pages of results. The default is 100; the maximum allowed page size is also 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If <code>NextToken</code> is returned, there are more results available. The value of <code>NextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>NextToken</code> is returned, there are more results available. The value of <code>NextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If <code>NextToken</code> is returned, there are more results available. The value of <code>NextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListWatchlistsInput`](crate::operation::list_watchlists::ListWatchlistsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_watchlists::ListWatchlistsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_watchlists::ListWatchlistsInput {
            domain_id: self.domain_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
