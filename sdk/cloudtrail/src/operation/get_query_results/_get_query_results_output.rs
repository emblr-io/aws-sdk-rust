// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetQueryResultsOutput {
    /// <p>The status of the query. Values include <code>QUEUED</code>, <code>RUNNING</code>, <code>FINISHED</code>, <code>FAILED</code>, <code>TIMED_OUT</code>, or <code>CANCELLED</code>.</p>
    pub query_status: ::std::option::Option<crate::types::QueryStatus>,
    /// <p>Shows the count of query results.</p>
    pub query_statistics: ::std::option::Option<crate::types::QueryStatistics>,
    /// <p>Contains the individual event results of the query.</p>
    pub query_result_rows:
        ::std::option::Option<::std::vec::Vec<::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>>>,
    /// <p>A token you can use to get the next page of query results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The error message returned if a query failed.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsOutput {
    /// <p>The status of the query. Values include <code>QUEUED</code>, <code>RUNNING</code>, <code>FINISHED</code>, <code>FAILED</code>, <code>TIMED_OUT</code>, or <code>CANCELLED</code>.</p>
    pub fn query_status(&self) -> ::std::option::Option<&crate::types::QueryStatus> {
        self.query_status.as_ref()
    }
    /// <p>Shows the count of query results.</p>
    pub fn query_statistics(&self) -> ::std::option::Option<&crate::types::QueryStatistics> {
        self.query_statistics.as_ref()
    }
    /// <p>Contains the individual event results of the query.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.query_result_rows.is_none()`.
    pub fn query_result_rows(&self) -> &[::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>] {
        self.query_result_rows.as_deref().unwrap_or_default()
    }
    /// <p>A token you can use to get the next page of query results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The error message returned if a query failed.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetQueryResultsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetQueryResultsOutput {
    /// Creates a new builder-style object to manufacture [`GetQueryResultsOutput`](crate::operation::get_query_results::GetQueryResultsOutput).
    pub fn builder() -> crate::operation::get_query_results::builders::GetQueryResultsOutputBuilder {
        crate::operation::get_query_results::builders::GetQueryResultsOutputBuilder::default()
    }
}

/// A builder for [`GetQueryResultsOutput`](crate::operation::get_query_results::GetQueryResultsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetQueryResultsOutputBuilder {
    pub(crate) query_status: ::std::option::Option<crate::types::QueryStatus>,
    pub(crate) query_statistics: ::std::option::Option<crate::types::QueryStatistics>,
    pub(crate) query_result_rows:
        ::std::option::Option<::std::vec::Vec<::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueryResultsOutputBuilder {
    /// <p>The status of the query. Values include <code>QUEUED</code>, <code>RUNNING</code>, <code>FINISHED</code>, <code>FAILED</code>, <code>TIMED_OUT</code>, or <code>CANCELLED</code>.</p>
    pub fn query_status(mut self, input: crate::types::QueryStatus) -> Self {
        self.query_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the query. Values include <code>QUEUED</code>, <code>RUNNING</code>, <code>FINISHED</code>, <code>FAILED</code>, <code>TIMED_OUT</code>, or <code>CANCELLED</code>.</p>
    pub fn set_query_status(mut self, input: ::std::option::Option<crate::types::QueryStatus>) -> Self {
        self.query_status = input;
        self
    }
    /// <p>The status of the query. Values include <code>QUEUED</code>, <code>RUNNING</code>, <code>FINISHED</code>, <code>FAILED</code>, <code>TIMED_OUT</code>, or <code>CANCELLED</code>.</p>
    pub fn get_query_status(&self) -> &::std::option::Option<crate::types::QueryStatus> {
        &self.query_status
    }
    /// <p>Shows the count of query results.</p>
    pub fn query_statistics(mut self, input: crate::types::QueryStatistics) -> Self {
        self.query_statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Shows the count of query results.</p>
    pub fn set_query_statistics(mut self, input: ::std::option::Option<crate::types::QueryStatistics>) -> Self {
        self.query_statistics = input;
        self
    }
    /// <p>Shows the count of query results.</p>
    pub fn get_query_statistics(&self) -> &::std::option::Option<crate::types::QueryStatistics> {
        &self.query_statistics
    }
    /// Appends an item to `query_result_rows`.
    ///
    /// To override the contents of this collection use [`set_query_result_rows`](Self::set_query_result_rows).
    ///
    /// <p>Contains the individual event results of the query.</p>
    pub fn query_result_rows(mut self, input: ::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        let mut v = self.query_result_rows.unwrap_or_default();
        v.push(input);
        self.query_result_rows = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the individual event results of the query.</p>
    pub fn set_query_result_rows(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>>>,
    ) -> Self {
        self.query_result_rows = input;
        self
    }
    /// <p>Contains the individual event results of the query.</p>
    pub fn get_query_result_rows(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<::std::vec::Vec<::std::collections::HashMap<::std::string::String, ::std::string::String>>>> {
        &self.query_result_rows
    }
    /// <p>A token you can use to get the next page of query results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token you can use to get the next page of query results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token you can use to get the next page of query results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The error message returned if a query failed.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message returned if a query failed.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message returned if a query failed.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetQueryResultsOutput`](crate::operation::get_query_results::GetQueryResultsOutput).
    pub fn build(self) -> crate::operation::get_query_results::GetQueryResultsOutput {
        crate::operation::get_query_results::GetQueryResultsOutput {
            query_status: self.query_status,
            query_statistics: self.query_statistics,
            query_result_rows: self.query_result_rows,
            next_token: self.next_token,
            error_message: self.error_message,
            _request_id: self._request_id,
        }
    }
}
