// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Represents output for ListAnalyzableServers operation.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAnalyzableServersOutput {
    /// The list of analyzable servers with summary information about each server.
    pub analyzable_servers: ::std::option::Option<::std::vec::Vec<crate::types::AnalyzableServerSummary>>,
    /// The token you use to retrieve the next set of results, or null if there are no more results.
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnalyzableServersOutput {
    /// The list of analyzable servers with summary information about each server.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.analyzable_servers.is_none()`.
    pub fn analyzable_servers(&self) -> &[crate::types::AnalyzableServerSummary] {
        self.analyzable_servers.as_deref().unwrap_or_default()
    }
    /// The token you use to retrieve the next set of results, or null if there are no more results.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAnalyzableServersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAnalyzableServersOutput {
    /// Creates a new builder-style object to manufacture [`ListAnalyzableServersOutput`](crate::operation::list_analyzable_servers::ListAnalyzableServersOutput).
    pub fn builder() -> crate::operation::list_analyzable_servers::builders::ListAnalyzableServersOutputBuilder {
        crate::operation::list_analyzable_servers::builders::ListAnalyzableServersOutputBuilder::default()
    }
}

/// A builder for [`ListAnalyzableServersOutput`](crate::operation::list_analyzable_servers::ListAnalyzableServersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAnalyzableServersOutputBuilder {
    pub(crate) analyzable_servers: ::std::option::Option<::std::vec::Vec<crate::types::AnalyzableServerSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAnalyzableServersOutputBuilder {
    /// Appends an item to `analyzable_servers`.
    ///
    /// To override the contents of this collection use [`set_analyzable_servers`](Self::set_analyzable_servers).
    ///
    /// The list of analyzable servers with summary information about each server.
    pub fn analyzable_servers(mut self, input: crate::types::AnalyzableServerSummary) -> Self {
        let mut v = self.analyzable_servers.unwrap_or_default();
        v.push(input);
        self.analyzable_servers = ::std::option::Option::Some(v);
        self
    }
    /// The list of analyzable servers with summary information about each server.
    pub fn set_analyzable_servers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AnalyzableServerSummary>>) -> Self {
        self.analyzable_servers = input;
        self
    }
    /// The list of analyzable servers with summary information about each server.
    pub fn get_analyzable_servers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AnalyzableServerSummary>> {
        &self.analyzable_servers
    }
    /// The token you use to retrieve the next set of results, or null if there are no more results.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// The token you use to retrieve the next set of results, or null if there are no more results.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// The token you use to retrieve the next set of results, or null if there are no more results.
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
    /// Consumes the builder and constructs a [`ListAnalyzableServersOutput`](crate::operation::list_analyzable_servers::ListAnalyzableServersOutput).
    pub fn build(self) -> crate::operation::list_analyzable_servers::ListAnalyzableServersOutput {
        crate::operation::list_analyzable_servers::ListAnalyzableServersOutput {
            analyzable_servers: self.analyzable_servers,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
