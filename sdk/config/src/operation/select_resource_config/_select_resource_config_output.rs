// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SelectResourceConfigOutput {
    /// <p>Returns the results for the SQL query.</p>
    pub results: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Returns the <code>QueryInfo</code> object.</p>
    pub query_info: ::std::option::Option<crate::types::QueryInfo>,
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SelectResourceConfigOutput {
    /// <p>Returns the results for the SQL query.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.results.is_none()`.
    pub fn results(&self) -> &[::std::string::String] {
        self.results.as_deref().unwrap_or_default()
    }
    /// <p>Returns the <code>QueryInfo</code> object.</p>
    pub fn query_info(&self) -> ::std::option::Option<&crate::types::QueryInfo> {
        self.query_info.as_ref()
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SelectResourceConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SelectResourceConfigOutput {
    /// Creates a new builder-style object to manufacture [`SelectResourceConfigOutput`](crate::operation::select_resource_config::SelectResourceConfigOutput).
    pub fn builder() -> crate::operation::select_resource_config::builders::SelectResourceConfigOutputBuilder {
        crate::operation::select_resource_config::builders::SelectResourceConfigOutputBuilder::default()
    }
}

/// A builder for [`SelectResourceConfigOutput`](crate::operation::select_resource_config::SelectResourceConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SelectResourceConfigOutputBuilder {
    pub(crate) results: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) query_info: ::std::option::Option<crate::types::QueryInfo>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SelectResourceConfigOutputBuilder {
    /// Appends an item to `results`.
    ///
    /// To override the contents of this collection use [`set_results`](Self::set_results).
    ///
    /// <p>Returns the results for the SQL query.</p>
    pub fn results(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.results.unwrap_or_default();
        v.push(input.into());
        self.results = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the results for the SQL query.</p>
    pub fn set_results(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.results = input;
        self
    }
    /// <p>Returns the results for the SQL query.</p>
    pub fn get_results(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.results
    }
    /// <p>Returns the <code>QueryInfo</code> object.</p>
    pub fn query_info(mut self, input: crate::types::QueryInfo) -> Self {
        self.query_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the <code>QueryInfo</code> object.</p>
    pub fn set_query_info(mut self, input: ::std::option::Option<crate::types::QueryInfo>) -> Self {
        self.query_info = input;
        self
    }
    /// <p>Returns the <code>QueryInfo</code> object.</p>
    pub fn get_query_info(&self) -> &::std::option::Option<crate::types::QueryInfo> {
        &self.query_info
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
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
    /// Consumes the builder and constructs a [`SelectResourceConfigOutput`](crate::operation::select_resource_config::SelectResourceConfigOutput).
    pub fn build(self) -> crate::operation::select_resource_config::SelectResourceConfigOutput {
        crate::operation::select_resource_config::SelectResourceConfigOutput {
            results: self.results,
            query_info: self.query_info,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
