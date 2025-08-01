// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNotificationEventsOutput {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The list of notification events.</p>
    pub notification_events: ::std::vec::Vec<crate::types::NotificationEventOverview>,
    _request_id: Option<String>,
}
impl ListNotificationEventsOutput {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The list of notification events.</p>
    pub fn notification_events(&self) -> &[crate::types::NotificationEventOverview] {
        use std::ops::Deref;
        self.notification_events.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListNotificationEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListNotificationEventsOutput {
    /// Creates a new builder-style object to manufacture [`ListNotificationEventsOutput`](crate::operation::list_notification_events::ListNotificationEventsOutput).
    pub fn builder() -> crate::operation::list_notification_events::builders::ListNotificationEventsOutputBuilder {
        crate::operation::list_notification_events::builders::ListNotificationEventsOutputBuilder::default()
    }
}

/// A builder for [`ListNotificationEventsOutput`](crate::operation::list_notification_events::ListNotificationEventsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNotificationEventsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) notification_events: ::std::option::Option<::std::vec::Vec<crate::types::NotificationEventOverview>>,
    _request_id: Option<String>,
}
impl ListNotificationEventsOutputBuilder {
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token. If a non-null pagination token is returned in a result, pass its value in another request to retrieve more entries.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `notification_events`.
    ///
    /// To override the contents of this collection use [`set_notification_events`](Self::set_notification_events).
    ///
    /// <p>The list of notification events.</p>
    pub fn notification_events(mut self, input: crate::types::NotificationEventOverview) -> Self {
        let mut v = self.notification_events.unwrap_or_default();
        v.push(input);
        self.notification_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of notification events.</p>
    pub fn set_notification_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotificationEventOverview>>) -> Self {
        self.notification_events = input;
        self
    }
    /// <p>The list of notification events.</p>
    pub fn get_notification_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotificationEventOverview>> {
        &self.notification_events
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListNotificationEventsOutput`](crate::operation::list_notification_events::ListNotificationEventsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`notification_events`](crate::operation::list_notification_events::builders::ListNotificationEventsOutputBuilder::notification_events)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_notification_events::ListNotificationEventsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_notification_events::ListNotificationEventsOutput {
            next_token: self.next_token,
            notification_events: self.notification_events.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "notification_events",
                    "notification_events was not specified but it is required when building ListNotificationEventsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
