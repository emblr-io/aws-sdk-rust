// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPreparedStatementOutput {
    /// <p>The name of the prepared statement that was retrieved.</p>
    pub prepared_statement: ::std::option::Option<crate::types::PreparedStatement>,
    _request_id: Option<String>,
}
impl GetPreparedStatementOutput {
    /// <p>The name of the prepared statement that was retrieved.</p>
    pub fn prepared_statement(&self) -> ::std::option::Option<&crate::types::PreparedStatement> {
        self.prepared_statement.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPreparedStatementOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPreparedStatementOutput {
    /// Creates a new builder-style object to manufacture [`GetPreparedStatementOutput`](crate::operation::get_prepared_statement::GetPreparedStatementOutput).
    pub fn builder() -> crate::operation::get_prepared_statement::builders::GetPreparedStatementOutputBuilder {
        crate::operation::get_prepared_statement::builders::GetPreparedStatementOutputBuilder::default()
    }
}

/// A builder for [`GetPreparedStatementOutput`](crate::operation::get_prepared_statement::GetPreparedStatementOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPreparedStatementOutputBuilder {
    pub(crate) prepared_statement: ::std::option::Option<crate::types::PreparedStatement>,
    _request_id: Option<String>,
}
impl GetPreparedStatementOutputBuilder {
    /// <p>The name of the prepared statement that was retrieved.</p>
    pub fn prepared_statement(mut self, input: crate::types::PreparedStatement) -> Self {
        self.prepared_statement = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the prepared statement that was retrieved.</p>
    pub fn set_prepared_statement(mut self, input: ::std::option::Option<crate::types::PreparedStatement>) -> Self {
        self.prepared_statement = input;
        self
    }
    /// <p>The name of the prepared statement that was retrieved.</p>
    pub fn get_prepared_statement(&self) -> &::std::option::Option<crate::types::PreparedStatement> {
        &self.prepared_statement
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPreparedStatementOutput`](crate::operation::get_prepared_statement::GetPreparedStatementOutput).
    pub fn build(self) -> crate::operation::get_prepared_statement::GetPreparedStatementOutput {
        crate::operation::get_prepared_statement::GetPreparedStatementOutput {
            prepared_statement: self.prepared_statement,
            _request_id: self._request_id,
        }
    }
}
