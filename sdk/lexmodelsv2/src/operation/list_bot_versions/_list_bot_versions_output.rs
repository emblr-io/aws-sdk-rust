// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBotVersionsOutput {
    /// <p>The identifier of the bot to list versions for.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>Summary information for the bot versions that meet the filter criteria specified in the request. The length of the list is specified in the <code>maxResults</code> parameter of the request. If there are more versions available, the <code>nextToken</code> field contains a token to get the next page of results.</p>
    pub bot_version_summaries: ::std::option::Option<::std::vec::Vec<crate::types::BotVersionSummary>>,
    /// <p>A token that indicates whether there are more results to return in a response to the <code>ListBotVersions</code> operation. If the <code>nextToken</code> field is present, you send the contents as the <code>nextToken</code> parameter of a <code>ListBotAliases</code> operation request to get the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListBotVersionsOutput {
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>Summary information for the bot versions that meet the filter criteria specified in the request. The length of the list is specified in the <code>maxResults</code> parameter of the request. If there are more versions available, the <code>nextToken</code> field contains a token to get the next page of results.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bot_version_summaries.is_none()`.
    pub fn bot_version_summaries(&self) -> &[crate::types::BotVersionSummary] {
        self.bot_version_summaries.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates whether there are more results to return in a response to the <code>ListBotVersions</code> operation. If the <code>nextToken</code> field is present, you send the contents as the <code>nextToken</code> parameter of a <code>ListBotAliases</code> operation request to get the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListBotVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListBotVersionsOutput {
    /// Creates a new builder-style object to manufacture [`ListBotVersionsOutput`](crate::operation::list_bot_versions::ListBotVersionsOutput).
    pub fn builder() -> crate::operation::list_bot_versions::builders::ListBotVersionsOutputBuilder {
        crate::operation::list_bot_versions::builders::ListBotVersionsOutputBuilder::default()
    }
}

/// A builder for [`ListBotVersionsOutput`](crate::operation::list_bot_versions::ListBotVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBotVersionsOutputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version_summaries: ::std::option::Option<::std::vec::Vec<crate::types::BotVersionSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListBotVersionsOutputBuilder {
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier of the bot to list versions for.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// Appends an item to `bot_version_summaries`.
    ///
    /// To override the contents of this collection use [`set_bot_version_summaries`](Self::set_bot_version_summaries).
    ///
    /// <p>Summary information for the bot versions that meet the filter criteria specified in the request. The length of the list is specified in the <code>maxResults</code> parameter of the request. If there are more versions available, the <code>nextToken</code> field contains a token to get the next page of results.</p>
    pub fn bot_version_summaries(mut self, input: crate::types::BotVersionSummary) -> Self {
        let mut v = self.bot_version_summaries.unwrap_or_default();
        v.push(input);
        self.bot_version_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>Summary information for the bot versions that meet the filter criteria specified in the request. The length of the list is specified in the <code>maxResults</code> parameter of the request. If there are more versions available, the <code>nextToken</code> field contains a token to get the next page of results.</p>
    pub fn set_bot_version_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BotVersionSummary>>) -> Self {
        self.bot_version_summaries = input;
        self
    }
    /// <p>Summary information for the bot versions that meet the filter criteria specified in the request. The length of the list is specified in the <code>maxResults</code> parameter of the request. If there are more versions available, the <code>nextToken</code> field contains a token to get the next page of results.</p>
    pub fn get_bot_version_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BotVersionSummary>> {
        &self.bot_version_summaries
    }
    /// <p>A token that indicates whether there are more results to return in a response to the <code>ListBotVersions</code> operation. If the <code>nextToken</code> field is present, you send the contents as the <code>nextToken</code> parameter of a <code>ListBotAliases</code> operation request to get the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates whether there are more results to return in a response to the <code>ListBotVersions</code> operation. If the <code>nextToken</code> field is present, you send the contents as the <code>nextToken</code> parameter of a <code>ListBotAliases</code> operation request to get the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates whether there are more results to return in a response to the <code>ListBotVersions</code> operation. If the <code>nextToken</code> field is present, you send the contents as the <code>nextToken</code> parameter of a <code>ListBotAliases</code> operation request to get the next page of results.</p>
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
    /// Consumes the builder and constructs a [`ListBotVersionsOutput`](crate::operation::list_bot_versions::ListBotVersionsOutput).
    pub fn build(self) -> crate::operation::list_bot_versions::ListBotVersionsOutput {
        crate::operation::list_bot_versions::ListBotVersionsOutput {
            bot_id: self.bot_id,
            bot_version_summaries: self.bot_version_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
