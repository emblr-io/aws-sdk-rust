// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMatchmakingConfigurationsOutput {
    /// <p>A collection of requested matchmaking configurations.</p>
    pub configurations: ::std::option::Option<::std::vec::Vec<crate::types::MatchmakingConfiguration>>,
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeMatchmakingConfigurationsOutput {
    /// <p>A collection of requested matchmaking configurations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configurations.is_none()`.
    pub fn configurations(&self) -> &[crate::types::MatchmakingConfiguration] {
        self.configurations.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates where to resume retrieving results on the next call to this operation. If no token is returned, these results represent the end of the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeMatchmakingConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeMatchmakingConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeMatchmakingConfigurationsOutput`](crate::operation::describe_matchmaking_configurations::DescribeMatchmakingConfigurationsOutput).
    pub fn builder() -> crate::operation::describe_matchmaking_configurations::builders::DescribeMatchmakingConfigurationsOutputBuilder {
        crate::operation::describe_matchmaking_configurations::builders::DescribeMatchmakingConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`DescribeMatchmakingConfigurationsOutput`](crate::operation::describe_matchmaking_configurations::DescribeMatchmakingConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMatchmakingConfigurationsOutputBuilder {
    pub(crate) configurations: ::std::option::Option<::std::vec::Vec<crate::types::MatchmakingConfiguration>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeMatchmakingConfigurationsOutputBuilder {
    /// Appends an item to `configurations`.
    ///
    /// To override the contents of this collection use [`set_configurations`](Self::set_configurations).
    ///
    /// <p>A collection of requested matchmaking configurations.</p>
    pub fn configurations(mut self, input: crate::types::MatchmakingConfiguration) -> Self {
        let mut v = self.configurations.unwrap_or_default();
        v.push(input);
        self.configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of requested matchmaking configurations.</p>
    pub fn set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MatchmakingConfiguration>>) -> Self {
        self.configurations = input;
        self
    }
    /// <p>A collection of requested matchmaking configurations.</p>
    pub fn get_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MatchmakingConfiguration>> {
        &self.configurations
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
    /// Consumes the builder and constructs a [`DescribeMatchmakingConfigurationsOutput`](crate::operation::describe_matchmaking_configurations::DescribeMatchmakingConfigurationsOutput).
    pub fn build(self) -> crate::operation::describe_matchmaking_configurations::DescribeMatchmakingConfigurationsOutput {
        crate::operation::describe_matchmaking_configurations::DescribeMatchmakingConfigurationsOutput {
            configurations: self.configurations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
