// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response elements represent the output of a request to run one or more SQL statements.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteSqlOutput {
    /// <p>The results of the SQL statement or statements.</p>
    pub sql_statement_results: ::std::option::Option<::std::vec::Vec<crate::types::SqlStatementResult>>,
    _request_id: Option<String>,
}
impl ExecuteSqlOutput {
    /// <p>The results of the SQL statement or statements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sql_statement_results.is_none()`.
    pub fn sql_statement_results(&self) -> &[crate::types::SqlStatementResult] {
        self.sql_statement_results.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ExecuteSqlOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExecuteSqlOutput {
    /// Creates a new builder-style object to manufacture [`ExecuteSqlOutput`](crate::operation::execute_sql::ExecuteSqlOutput).
    pub fn builder() -> crate::operation::execute_sql::builders::ExecuteSqlOutputBuilder {
        crate::operation::execute_sql::builders::ExecuteSqlOutputBuilder::default()
    }
}

/// A builder for [`ExecuteSqlOutput`](crate::operation::execute_sql::ExecuteSqlOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteSqlOutputBuilder {
    pub(crate) sql_statement_results: ::std::option::Option<::std::vec::Vec<crate::types::SqlStatementResult>>,
    _request_id: Option<String>,
}
impl ExecuteSqlOutputBuilder {
    /// Appends an item to `sql_statement_results`.
    ///
    /// To override the contents of this collection use [`set_sql_statement_results`](Self::set_sql_statement_results).
    ///
    /// <p>The results of the SQL statement or statements.</p>
    pub fn sql_statement_results(mut self, input: crate::types::SqlStatementResult) -> Self {
        let mut v = self.sql_statement_results.unwrap_or_default();
        v.push(input);
        self.sql_statement_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>The results of the SQL statement or statements.</p>
    pub fn set_sql_statement_results(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SqlStatementResult>>) -> Self {
        self.sql_statement_results = input;
        self
    }
    /// <p>The results of the SQL statement or statements.</p>
    pub fn get_sql_statement_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SqlStatementResult>> {
        &self.sql_statement_results
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ExecuteSqlOutput`](crate::operation::execute_sql::ExecuteSqlOutput).
    pub fn build(self) -> crate::operation::execute_sql::ExecuteSqlOutput {
        crate::operation::execute_sql::ExecuteSqlOutput {
            sql_statement_results: self.sql_statement_results,
            _request_id: self._request_id,
        }
    }
}
