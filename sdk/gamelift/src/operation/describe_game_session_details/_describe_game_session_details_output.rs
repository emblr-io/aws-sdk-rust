// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGameSessionDetailsOutput {
    /// <p>A collection of properties for each game session that matches the request.</p>
    pub game_session_details: ::std::option::Option<::std::vec::Vec<crate::types::GameSessionDetail>>,
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGameSessionDetailsOutput {
    /// <p>A collection of properties for each game session that matches the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.game_session_details.is_none()`.
    pub fn game_session_details(&self) -> &[crate::types::GameSessionDetail] {
        self.game_session_details.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeGameSessionDetailsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeGameSessionDetailsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeGameSessionDetailsOutput`](crate::operation::describe_game_session_details::DescribeGameSessionDetailsOutput).
    pub fn builder() -> crate::operation::describe_game_session_details::builders::DescribeGameSessionDetailsOutputBuilder {
        crate::operation::describe_game_session_details::builders::DescribeGameSessionDetailsOutputBuilder::default()
    }
}

/// A builder for [`DescribeGameSessionDetailsOutput`](crate::operation::describe_game_session_details::DescribeGameSessionDetailsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGameSessionDetailsOutputBuilder {
    pub(crate) game_session_details: ::std::option::Option<::std::vec::Vec<crate::types::GameSessionDetail>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGameSessionDetailsOutputBuilder {
    /// Appends an item to `game_session_details`.
    ///
    /// To override the contents of this collection use [`set_game_session_details`](Self::set_game_session_details).
    ///
    /// <p>A collection of properties for each game session that matches the request.</p>
    pub fn game_session_details(mut self, input: crate::types::GameSessionDetail) -> Self {
        let mut v = self.game_session_details.unwrap_or_default();
        v.push(input);
        self.game_session_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of properties for each game session that matches the request.</p>
    pub fn set_game_session_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GameSessionDetail>>) -> Self {
        self.game_session_details = input;
        self
    }
    /// <p>A collection of properties for each game session that matches the request.</p>
    pub fn get_game_session_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GameSessionDetail>> {
        &self.game_session_details
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
    /// Consumes the builder and constructs a [`DescribeGameSessionDetailsOutput`](crate::operation::describe_game_session_details::DescribeGameSessionDetailsOutput).
    pub fn build(self) -> crate::operation::describe_game_session_details::DescribeGameSessionDetailsOutput {
        crate::operation::describe_game_session_details::DescribeGameSessionDetailsOutput {
            game_session_details: self.game_session_details,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
