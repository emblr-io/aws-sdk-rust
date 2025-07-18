// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCrawlsInput {
    /// <p>The name of the crawler whose runs you want to retrieve.</p>
    pub crawler_name: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return. The default is 20, and maximum is 100.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Filters the crawls by the criteria you specify in a list of <code>CrawlsFilter</code> objects.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::CrawlsFilter>>,
    /// <p>A continuation token, if this is a continuation call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListCrawlsInput {
    /// <p>The name of the crawler whose runs you want to retrieve.</p>
    pub fn crawler_name(&self) -> ::std::option::Option<&str> {
        self.crawler_name.as_deref()
    }
    /// <p>The maximum number of results to return. The default is 20, and maximum is 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Filters the crawls by the criteria you specify in a list of <code>CrawlsFilter</code> objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::CrawlsFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListCrawlsInput {
    /// Creates a new builder-style object to manufacture [`ListCrawlsInput`](crate::operation::list_crawls::ListCrawlsInput).
    pub fn builder() -> crate::operation::list_crawls::builders::ListCrawlsInputBuilder {
        crate::operation::list_crawls::builders::ListCrawlsInputBuilder::default()
    }
}

/// A builder for [`ListCrawlsInput`](crate::operation::list_crawls::ListCrawlsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCrawlsInputBuilder {
    pub(crate) crawler_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::CrawlsFilter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListCrawlsInputBuilder {
    /// <p>The name of the crawler whose runs you want to retrieve.</p>
    /// This field is required.
    pub fn crawler_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.crawler_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the crawler whose runs you want to retrieve.</p>
    pub fn set_crawler_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.crawler_name = input;
        self
    }
    /// <p>The name of the crawler whose runs you want to retrieve.</p>
    pub fn get_crawler_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.crawler_name
    }
    /// <p>The maximum number of results to return. The default is 20, and maximum is 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. The default is 20, and maximum is 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return. The default is 20, and maximum is 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Filters the crawls by the criteria you specify in a list of <code>CrawlsFilter</code> objects.</p>
    pub fn filters(mut self, input: crate::types::CrawlsFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the crawls by the criteria you specify in a list of <code>CrawlsFilter</code> objects.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CrawlsFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Filters the crawls by the criteria you specify in a list of <code>CrawlsFilter</code> objects.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CrawlsFilter>> {
        &self.filters
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListCrawlsInput`](crate::operation::list_crawls::ListCrawlsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_crawls::ListCrawlsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_crawls::ListCrawlsInput {
            crawler_name: self.crawler_name,
            max_results: self.max_results,
            filters: self.filters,
            next_token: self.next_token,
        })
    }
}
