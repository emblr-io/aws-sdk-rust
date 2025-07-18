// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetContainerLogOutput {
    /// <p>An array of objects that describe the log events of a container.</p>
    pub log_events: ::std::option::Option<::std::vec::Vec<crate::types::ContainerServiceLogEvent>>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetContainerLog</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetContainerLogOutput {
    /// <p>An array of objects that describe the log events of a container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_events.is_none()`.
    pub fn log_events(&self) -> &[crate::types::ContainerServiceLogEvent] {
        self.log_events.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetContainerLog</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetContainerLogOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetContainerLogOutput {
    /// Creates a new builder-style object to manufacture [`GetContainerLogOutput`](crate::operation::get_container_log::GetContainerLogOutput).
    pub fn builder() -> crate::operation::get_container_log::builders::GetContainerLogOutputBuilder {
        crate::operation::get_container_log::builders::GetContainerLogOutputBuilder::default()
    }
}

/// A builder for [`GetContainerLogOutput`](crate::operation::get_container_log::GetContainerLogOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetContainerLogOutputBuilder {
    pub(crate) log_events: ::std::option::Option<::std::vec::Vec<crate::types::ContainerServiceLogEvent>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetContainerLogOutputBuilder {
    /// Appends an item to `log_events`.
    ///
    /// To override the contents of this collection use [`set_log_events`](Self::set_log_events).
    ///
    /// <p>An array of objects that describe the log events of a container.</p>
    pub fn log_events(mut self, input: crate::types::ContainerServiceLogEvent) -> Self {
        let mut v = self.log_events.unwrap_or_default();
        v.push(input);
        self.log_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the log events of a container.</p>
    pub fn set_log_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContainerServiceLogEvent>>) -> Self {
        self.log_events = input;
        self
    }
    /// <p>An array of objects that describe the log events of a container.</p>
    pub fn get_log_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContainerServiceLogEvent>> {
        &self.log_events
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetContainerLog</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetContainerLog</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetContainerLog</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
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
    /// Consumes the builder and constructs a [`GetContainerLogOutput`](crate::operation::get_container_log::GetContainerLogOutput).
    pub fn build(self) -> crate::operation::get_container_log::GetContainerLogOutput {
        crate::operation::get_container_log::GetContainerLogOutput {
            log_events: self.log_events,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
