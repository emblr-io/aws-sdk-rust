// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabasesOutput {
    /// <p>An object describing the result of your get relational databases request.</p>
    pub relational_databases: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabase>>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabases</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRelationalDatabasesOutput {
    /// <p>An object describing the result of your get relational databases request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.relational_databases.is_none()`.
    pub fn relational_databases(&self) -> &[crate::types::RelationalDatabase] {
        self.relational_databases.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabases</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetRelationalDatabasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRelationalDatabasesOutput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabasesOutput`](crate::operation::get_relational_databases::GetRelationalDatabasesOutput).
    pub fn builder() -> crate::operation::get_relational_databases::builders::GetRelationalDatabasesOutputBuilder {
        crate::operation::get_relational_databases::builders::GetRelationalDatabasesOutputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabasesOutput`](crate::operation::get_relational_databases::GetRelationalDatabasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabasesOutputBuilder {
    pub(crate) relational_databases: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabase>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRelationalDatabasesOutputBuilder {
    /// Appends an item to `relational_databases`.
    ///
    /// To override the contents of this collection use [`set_relational_databases`](Self::set_relational_databases).
    ///
    /// <p>An object describing the result of your get relational databases request.</p>
    pub fn relational_databases(mut self, input: crate::types::RelationalDatabase) -> Self {
        let mut v = self.relational_databases.unwrap_or_default();
        v.push(input);
        self.relational_databases = ::std::option::Option::Some(v);
        self
    }
    /// <p>An object describing the result of your get relational databases request.</p>
    pub fn set_relational_databases(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabase>>) -> Self {
        self.relational_databases = input;
        self
    }
    /// <p>An object describing the result of your get relational databases request.</p>
    pub fn get_relational_databases(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabase>> {
        &self.relational_databases
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabases</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabases</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabases</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
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
    /// Consumes the builder and constructs a [`GetRelationalDatabasesOutput`](crate::operation::get_relational_databases::GetRelationalDatabasesOutput).
    pub fn build(self) -> crate::operation::get_relational_databases::GetRelationalDatabasesOutput {
        crate::operation::get_relational_databases::GetRelationalDatabasesOutput {
            relational_databases: self.relational_databases,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
