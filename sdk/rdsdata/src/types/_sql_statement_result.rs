// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a SQL statement.</p><note>
/// <p>This data structure is only used with the deprecated <code>ExecuteSql</code> operation. Use the <code>BatchExecuteStatement</code> or <code>ExecuteStatement</code> operation instead.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SqlStatementResult {
    /// <p>The result set of the SQL statement.</p>
    pub result_frame: ::std::option::Option<crate::types::ResultFrame>,
    /// <p>The number of records updated by a SQL statement.</p>
    pub number_of_records_updated: i64,
}
impl SqlStatementResult {
    /// <p>The result set of the SQL statement.</p>
    pub fn result_frame(&self) -> ::std::option::Option<&crate::types::ResultFrame> {
        self.result_frame.as_ref()
    }
    /// <p>The number of records updated by a SQL statement.</p>
    pub fn number_of_records_updated(&self) -> i64 {
        self.number_of_records_updated
    }
}
impl SqlStatementResult {
    /// Creates a new builder-style object to manufacture [`SqlStatementResult`](crate::types::SqlStatementResult).
    pub fn builder() -> crate::types::builders::SqlStatementResultBuilder {
        crate::types::builders::SqlStatementResultBuilder::default()
    }
}

/// A builder for [`SqlStatementResult`](crate::types::SqlStatementResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SqlStatementResultBuilder {
    pub(crate) result_frame: ::std::option::Option<crate::types::ResultFrame>,
    pub(crate) number_of_records_updated: ::std::option::Option<i64>,
}
impl SqlStatementResultBuilder {
    /// <p>The result set of the SQL statement.</p>
    pub fn result_frame(mut self, input: crate::types::ResultFrame) -> Self {
        self.result_frame = ::std::option::Option::Some(input);
        self
    }
    /// <p>The result set of the SQL statement.</p>
    pub fn set_result_frame(mut self, input: ::std::option::Option<crate::types::ResultFrame>) -> Self {
        self.result_frame = input;
        self
    }
    /// <p>The result set of the SQL statement.</p>
    pub fn get_result_frame(&self) -> &::std::option::Option<crate::types::ResultFrame> {
        &self.result_frame
    }
    /// <p>The number of records updated by a SQL statement.</p>
    pub fn number_of_records_updated(mut self, input: i64) -> Self {
        self.number_of_records_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of records updated by a SQL statement.</p>
    pub fn set_number_of_records_updated(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_records_updated = input;
        self
    }
    /// <p>The number of records updated by a SQL statement.</p>
    pub fn get_number_of_records_updated(&self) -> &::std::option::Option<i64> {
        &self.number_of_records_updated
    }
    /// Consumes the builder and constructs a [`SqlStatementResult`](crate::types::SqlStatementResult).
    pub fn build(self) -> crate::types::SqlStatementResult {
        crate::types::SqlStatementResult {
            result_frame: self.result_frame,
            number_of_records_updated: self.number_of_records_updated.unwrap_or_default(),
        }
    }
}
