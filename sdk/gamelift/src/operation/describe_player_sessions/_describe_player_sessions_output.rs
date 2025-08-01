// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePlayerSessionsOutput {
    /// <p>A collection of objects containing properties for each player session that matches the request.</p>
    pub player_sessions: ::std::option::Option<::std::vec::Vec<crate::types::PlayerSession>>,
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePlayerSessionsOutput {
    /// <p>A collection of objects containing properties for each player session that matches the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.player_sessions.is_none()`.
    pub fn player_sessions(&self) -> &[crate::types::PlayerSession] {
        self.player_sessions.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribePlayerSessionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribePlayerSessionsOutput {
    /// Creates a new builder-style object to manufacture [`DescribePlayerSessionsOutput`](crate::operation::describe_player_sessions::DescribePlayerSessionsOutput).
    pub fn builder() -> crate::operation::describe_player_sessions::builders::DescribePlayerSessionsOutputBuilder {
        crate::operation::describe_player_sessions::builders::DescribePlayerSessionsOutputBuilder::default()
    }
}

/// A builder for [`DescribePlayerSessionsOutput`](crate::operation::describe_player_sessions::DescribePlayerSessionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePlayerSessionsOutputBuilder {
    pub(crate) player_sessions: ::std::option::Option<::std::vec::Vec<crate::types::PlayerSession>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribePlayerSessionsOutputBuilder {
    /// Appends an item to `player_sessions`.
    ///
    /// To override the contents of this collection use [`set_player_sessions`](Self::set_player_sessions).
    ///
    /// <p>A collection of objects containing properties for each player session that matches the request.</p>
    pub fn player_sessions(mut self, input: crate::types::PlayerSession) -> Self {
        let mut v = self.player_sessions.unwrap_or_default();
        v.push(input);
        self.player_sessions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of objects containing properties for each player session that matches the request.</p>
    pub fn set_player_sessions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PlayerSession>>) -> Self {
        self.player_sessions = input;
        self
    }
    /// <p>A collection of objects containing properties for each player session that matches the request.</p>
    pub fn get_player_sessions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PlayerSession>> {
        &self.player_sessions
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
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
    /// Consumes the builder and constructs a [`DescribePlayerSessionsOutput`](crate::operation::describe_player_sessions::DescribePlayerSessionsOutput).
    pub fn build(self) -> crate::operation::describe_player_sessions::DescribePlayerSessionsOutput {
        crate::operation::describe_player_sessions::DescribePlayerSessionsOutput {
            player_sessions: self.player_sessions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
