// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabaseParametersOutput {
    /// <p>An object describing the result of your get relational database parameters request.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabaseParameter>>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabaseParameters</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseParametersOutput {
    /// <p>An object describing the result of your get relational database parameters request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::RelationalDatabaseParameter] {
        self.parameters.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabaseParameters</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetRelationalDatabaseParametersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRelationalDatabaseParametersOutput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabaseParametersOutput`](crate::operation::get_relational_database_parameters::GetRelationalDatabaseParametersOutput).
    pub fn builder() -> crate::operation::get_relational_database_parameters::builders::GetRelationalDatabaseParametersOutputBuilder {
        crate::operation::get_relational_database_parameters::builders::GetRelationalDatabaseParametersOutputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabaseParametersOutput`](crate::operation::get_relational_database_parameters::GetRelationalDatabaseParametersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabaseParametersOutputBuilder {
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabaseParameter>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseParametersOutputBuilder {
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>An object describing the result of your get relational database parameters request.</p>
    pub fn parameters(mut self, input: crate::types::RelationalDatabaseParameter) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An object describing the result of your get relational database parameters request.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabaseParameter>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>An object describing the result of your get relational database parameters request.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelationalDatabaseParameter>> {
        &self.parameters
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabaseParameters</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabaseParameters</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetRelationalDatabaseParameters</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
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
    /// Consumes the builder and constructs a [`GetRelationalDatabaseParametersOutput`](crate::operation::get_relational_database_parameters::GetRelationalDatabaseParametersOutput).
    pub fn build(self) -> crate::operation::get_relational_database_parameters::GetRelationalDatabaseParametersOutput {
        crate::operation::get_relational_database_parameters::GetRelationalDatabaseParametersOutput {
            parameters: self.parameters,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
