// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSessionAnalyticsDataOutput {
    /// <p>The unique identifier of the bot that the sessions belong to.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of objects, each of which contains information about a session with the bot.</p>
    pub sessions: ::std::option::Option<::std::vec::Vec<crate::types::SessionSpecification>>,
    _request_id: Option<String>,
}
impl ListSessionAnalyticsDataOutput {
    /// <p>The unique identifier of the bot that the sessions belong to.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of objects, each of which contains information about a session with the bot.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sessions.is_none()`.
    pub fn sessions(&self) -> &[crate::types::SessionSpecification] {
        self.sessions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSessionAnalyticsDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSessionAnalyticsDataOutput {
    /// Creates a new builder-style object to manufacture [`ListSessionAnalyticsDataOutput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataOutput).
    pub fn builder() -> crate::operation::list_session_analytics_data::builders::ListSessionAnalyticsDataOutputBuilder {
        crate::operation::list_session_analytics_data::builders::ListSessionAnalyticsDataOutputBuilder::default()
    }
}

/// A builder for [`ListSessionAnalyticsDataOutput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSessionAnalyticsDataOutputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sessions: ::std::option::Option<::std::vec::Vec<crate::types::SessionSpecification>>,
    _request_id: Option<String>,
}
impl ListSessionAnalyticsDataOutputBuilder {
    /// <p>The unique identifier of the bot that the sessions belong to.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the bot that the sessions belong to.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The unique identifier of the bot that the sessions belong to.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `sessions`.
    ///
    /// To override the contents of this collection use [`set_sessions`](Self::set_sessions).
    ///
    /// <p>A list of objects, each of which contains information about a session with the bot.</p>
    pub fn sessions(mut self, input: crate::types::SessionSpecification) -> Self {
        let mut v = self.sessions.unwrap_or_default();
        v.push(input);
        self.sessions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects, each of which contains information about a session with the bot.</p>
    pub fn set_sessions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SessionSpecification>>) -> Self {
        self.sessions = input;
        self
    }
    /// <p>A list of objects, each of which contains information about a session with the bot.</p>
    pub fn get_sessions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SessionSpecification>> {
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
    /// Consumes the builder and constructs a [`ListSessionAnalyticsDataOutput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataOutput).
    pub fn build(self) -> crate::operation::list_session_analytics_data::ListSessionAnalyticsDataOutput {
        crate::operation::list_session_analytics_data::ListSessionAnalyticsDataOutput {
            bot_id: self.bot_id,
            next_token: self.next_token,
            sessions: self.sessions,
            _request_id: self._request_id,
        }
    }
}
