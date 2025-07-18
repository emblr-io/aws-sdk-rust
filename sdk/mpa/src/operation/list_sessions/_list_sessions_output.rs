// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSessionsOutput {
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a next call to the operation to get more output. You can repeat this until the <code>NextToken</code> response element returns <code>null</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>ListSessionsResponseSession</code> objects. Contains details for the sessions.</p>
    pub sessions: ::std::option::Option<::std::vec::Vec<crate::types::ListSessionsResponseSession>>,
    _request_id: Option<String>,
}
impl ListSessionsOutput {
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a next call to the operation to get more output. You can repeat this until the <code>NextToken</code> response element returns <code>null</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of <code>ListSessionsResponseSession</code> objects. Contains details for the sessions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sessions.is_none()`.
    pub fn sessions(&self) -> &[crate::types::ListSessionsResponseSession] {
        self.sessions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSessionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSessionsOutput {
    /// Creates a new builder-style object to manufacture [`ListSessionsOutput`](crate::operation::list_sessions::ListSessionsOutput).
    pub fn builder() -> crate::operation::list_sessions::builders::ListSessionsOutputBuilder {
        crate::operation::list_sessions::builders::ListSessionsOutputBuilder::default()
    }
}

/// A builder for [`ListSessionsOutput`](crate::operation::list_sessions::ListSessionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSessionsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sessions: ::std::option::Option<::std::vec::Vec<crate::types::ListSessionsResponseSession>>,
    _request_id: Option<String>,
}
impl ListSessionsOutputBuilder {
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a next call to the operation to get more output. You can repeat this until the <code>NextToken</code> response element returns <code>null</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a next call to the operation to get more output. You can repeat this until the <code>NextToken</code> response element returns <code>null</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a next call to the operation to get more output. You can repeat this until the <code>NextToken</code> response element returns <code>null</code>.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `sessions`.
    ///
    /// To override the contents of this collection use [`set_sessions`](Self::set_sessions).
    ///
    /// <p>An array of <code>ListSessionsResponseSession</code> objects. Contains details for the sessions.</p>
    pub fn sessions(mut self, input: crate::types::ListSessionsResponseSession) -> Self {
        let mut v = self.sessions.unwrap_or_default();
        v.push(input);
        self.sessions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>ListSessionsResponseSession</code> objects. Contains details for the sessions.</p>
    pub fn set_sessions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ListSessionsResponseSession>>) -> Self {
        self.sessions = input;
        self
    }
    /// <p>An array of <code>ListSessionsResponseSession</code> objects. Contains details for the sessions.</p>
    pub fn get_sessions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ListSessionsResponseSession>> {
        &self.sessions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSessionsOutput`](crate::operation::list_sessions::ListSessionsOutput).
    pub fn build(self) -> crate::operation::list_sessions::ListSessionsOutput {
        crate::operation::list_sessions::ListSessionsOutput {
            next_token: self.next_token,
            sessions: self.sessions,
            _request_id: self._request_id,
        }
    }
}
