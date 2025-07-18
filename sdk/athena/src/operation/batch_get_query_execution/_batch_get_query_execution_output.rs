// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetQueryExecutionOutput {
    /// <p>Information about a query execution.</p>
    pub query_executions: ::std::option::Option<::std::vec::Vec<crate::types::QueryExecution>>,
    /// <p>Information about the query executions that failed to run.</p>
    pub unprocessed_query_execution_ids: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedQueryExecutionId>>,
    _request_id: Option<String>,
}
impl BatchGetQueryExecutionOutput {
    /// <p>Information about a query execution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.query_executions.is_none()`.
    pub fn query_executions(&self) -> &[crate::types::QueryExecution] {
        self.query_executions.as_deref().unwrap_or_default()
    }
    /// <p>Information about the query executions that failed to run.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unprocessed_query_execution_ids.is_none()`.
    pub fn unprocessed_query_execution_ids(&self) -> &[crate::types::UnprocessedQueryExecutionId] {
        self.unprocessed_query_execution_ids.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetQueryExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetQueryExecutionOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetQueryExecutionOutput`](crate::operation::batch_get_query_execution::BatchGetQueryExecutionOutput).
    pub fn builder() -> crate::operation::batch_get_query_execution::builders::BatchGetQueryExecutionOutputBuilder {
        crate::operation::batch_get_query_execution::builders::BatchGetQueryExecutionOutputBuilder::default()
    }
}

/// A builder for [`BatchGetQueryExecutionOutput`](crate::operation::batch_get_query_execution::BatchGetQueryExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetQueryExecutionOutputBuilder {
    pub(crate) query_executions: ::std::option::Option<::std::vec::Vec<crate::types::QueryExecution>>,
    pub(crate) unprocessed_query_execution_ids: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedQueryExecutionId>>,
    _request_id: Option<String>,
}
impl BatchGetQueryExecutionOutputBuilder {
    /// Appends an item to `query_executions`.
    ///
    /// To override the contents of this collection use [`set_query_executions`](Self::set_query_executions).
    ///
    /// <p>Information about a query execution.</p>
    pub fn query_executions(mut self, input: crate::types::QueryExecution) -> Self {
        let mut v = self.query_executions.unwrap_or_default();
        v.push(input);
        self.query_executions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about a query execution.</p>
    pub fn set_query_executions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::QueryExecution>>) -> Self {
        self.query_executions = input;
        self
    }
    /// <p>Information about a query execution.</p>
    pub fn get_query_executions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::QueryExecution>> {
        &self.query_executions
    }
    /// Appends an item to `unprocessed_query_execution_ids`.
    ///
    /// To override the contents of this collection use [`set_unprocessed_query_execution_ids`](Self::set_unprocessed_query_execution_ids).
    ///
    /// <p>Information about the query executions that failed to run.</p>
    pub fn unprocessed_query_execution_ids(mut self, input: crate::types::UnprocessedQueryExecutionId) -> Self {
        let mut v = self.unprocessed_query_execution_ids.unwrap_or_default();
        v.push(input);
        self.unprocessed_query_execution_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the query executions that failed to run.</p>
    pub fn set_unprocessed_query_execution_ids(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedQueryExecutionId>>,
    ) -> Self {
        self.unprocessed_query_execution_ids = input;
        self
    }
    /// <p>Information about the query executions that failed to run.</p>
    pub fn get_unprocessed_query_execution_ids(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnprocessedQueryExecutionId>> {
        &self.unprocessed_query_execution_ids
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetQueryExecutionOutput`](crate::operation::batch_get_query_execution::BatchGetQueryExecutionOutput).
    pub fn build(self) -> crate::operation::batch_get_query_execution::BatchGetQueryExecutionOutput {
        crate::operation::batch_get_query_execution::BatchGetQueryExecutionOutput {
            query_executions: self.query_executions,
            unprocessed_query_execution_ids: self.unprocessed_query_execution_ids,
            _request_id: self._request_id,
        }
    }
}
