// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStatementResultOutput {
    /// <p>The results of the SQL statement in JSON format.</p>
    pub records: ::std::vec::Vec<::std::vec::Vec<crate::types::Field>>,
    /// <p>The properties (metadata) of a column.</p>
    pub column_metadata: ::std::option::Option<::std::vec::Vec<crate::types::ColumnMetadata>>,
    /// <p>The total number of rows in the result set returned from a query. You can use this number to estimate the number of calls to the <code>GetStatementResult</code> operation needed to page through the results.</p>
    pub total_num_rows: i64,
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned NextToken value in the next NextToken parameter and retrying the command. If the NextToken field is empty, all response records have been retrieved for the request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetStatementResultOutput {
    /// <p>The results of the SQL statement in JSON format.</p>
    pub fn records(&self) -> &[::std::vec::Vec<crate::types::Field>] {
        use std::ops::Deref;
        self.records.deref()
    }
    /// <p>The properties (metadata) of a column.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.column_metadata.is_none()`.
    pub fn column_metadata(&self) -> &[crate::types::ColumnMetadata] {
        self.column_metadata.as_deref().unwrap_or_default()
    }
    /// <p>The total number of rows in the result set returned from a query. You can use this number to estimate the number of calls to the <code>GetStatementResult</code> operation needed to page through the results.</p>
    pub fn total_num_rows(&self) -> i64 {
        self.total_num_rows
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned NextToken value in the next NextToken parameter and retrying the command. If the NextToken field is empty, all response records have been retrieved for the request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetStatementResultOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetStatementResultOutput {
    /// Creates a new builder-style object to manufacture [`GetStatementResultOutput`](crate::operation::get_statement_result::GetStatementResultOutput).
    pub fn builder() -> crate::operation::get_statement_result::builders::GetStatementResultOutputBuilder {
        crate::operation::get_statement_result::builders::GetStatementResultOutputBuilder::default()
    }
}

/// A builder for [`GetStatementResultOutput`](crate::operation::get_statement_result::GetStatementResultOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStatementResultOutputBuilder {
    pub(crate) records: ::std::option::Option<::std::vec::Vec<::std::vec::Vec<crate::types::Field>>>,
    pub(crate) column_metadata: ::std::option::Option<::std::vec::Vec<crate::types::ColumnMetadata>>,
    pub(crate) total_num_rows: ::std::option::Option<i64>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetStatementResultOutputBuilder {
    /// Appends an item to `records`.
    ///
    /// To override the contents of this collection use [`set_records`](Self::set_records).
    ///
    /// <p>The results of the SQL statement in JSON format.</p>
    pub fn records(mut self, input: ::std::vec::Vec<crate::types::Field>) -> Self {
        let mut v = self.records.unwrap_or_default();
        v.push(input);
        self.records = ::std::option::Option::Some(v);
        self
    }
    /// <p>The results of the SQL statement in JSON format.</p>
    pub fn set_records(mut self, input: ::std::option::Option<::std::vec::Vec<::std::vec::Vec<crate::types::Field>>>) -> Self {
        self.records = input;
        self
    }
    /// <p>The results of the SQL statement in JSON format.</p>
    pub fn get_records(&self) -> &::std::option::Option<::std::vec::Vec<::std::vec::Vec<crate::types::Field>>> {
        &self.records
    }
    /// Appends an item to `column_metadata`.
    ///
    /// To override the contents of this collection use [`set_column_metadata`](Self::set_column_metadata).
    ///
    /// <p>The properties (metadata) of a column.</p>
    pub fn column_metadata(mut self, input: crate::types::ColumnMetadata) -> Self {
        let mut v = self.column_metadata.unwrap_or_default();
        v.push(input);
        self.column_metadata = ::std::option::Option::Some(v);
        self
    }
    /// <p>The properties (metadata) of a column.</p>
    pub fn set_column_metadata(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ColumnMetadata>>) -> Self {
        self.column_metadata = input;
        self
    }
    /// <p>The properties (metadata) of a column.</p>
    pub fn get_column_metadata(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ColumnMetadata>> {
        &self.column_metadata
    }
    /// <p>The total number of rows in the result set returned from a query. You can use this number to estimate the number of calls to the <code>GetStatementResult</code> operation needed to page through the results.</p>
    pub fn total_num_rows(mut self, input: i64) -> Self {
        self.total_num_rows = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of rows in the result set returned from a query. You can use this number to estimate the number of calls to the <code>GetStatementResult</code> operation needed to page through the results.</p>
    pub fn set_total_num_rows(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_num_rows = input;
        self
    }
    /// <p>The total number of rows in the result set returned from a query. You can use this number to estimate the number of calls to the <code>GetStatementResult</code> operation needed to page through the results.</p>
    pub fn get_total_num_rows(&self) -> &::std::option::Option<i64> {
        &self.total_num_rows
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned NextToken value in the next NextToken parameter and retrying the command. If the NextToken field is empty, all response records have been retrieved for the request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned NextToken value in the next NextToken parameter and retrying the command. If the NextToken field is empty, all response records have been retrieved for the request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned NextToken value in the next NextToken parameter and retrying the command. If the NextToken field is empty, all response records have been retrieved for the request.</p>
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
    /// Consumes the builder and constructs a [`GetStatementResultOutput`](crate::operation::get_statement_result::GetStatementResultOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`records`](crate::operation::get_statement_result::builders::GetStatementResultOutputBuilder::records)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_statement_result::GetStatementResultOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_statement_result::GetStatementResultOutput {
            records: self.records.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "records",
                    "records was not specified but it is required when building GetStatementResultOutput",
                )
            })?,
            column_metadata: self.column_metadata,
            total_num_rows: self.total_num_rows.unwrap_or_default(),
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
