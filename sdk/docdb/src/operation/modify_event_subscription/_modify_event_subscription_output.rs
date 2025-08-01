// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyEventSubscriptionOutput {
    /// <p>Detailed information about an event to which you have subscribed.</p>
    pub event_subscription: ::std::option::Option<crate::types::EventSubscription>,
    _request_id: Option<String>,
}
impl ModifyEventSubscriptionOutput {
    /// <p>Detailed information about an event to which you have subscribed.</p>
    pub fn event_subscription(&self) -> ::std::option::Option<&crate::types::EventSubscription> {
        self.event_subscription.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyEventSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyEventSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`ModifyEventSubscriptionOutput`](crate::operation::modify_event_subscription::ModifyEventSubscriptionOutput).
    pub fn builder() -> crate::operation::modify_event_subscription::builders::ModifyEventSubscriptionOutputBuilder {
        crate::operation::modify_event_subscription::builders::ModifyEventSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`ModifyEventSubscriptionOutput`](crate::operation::modify_event_subscription::ModifyEventSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyEventSubscriptionOutputBuilder {
    pub(crate) event_subscription: ::std::option::Option<crate::types::EventSubscription>,
    _request_id: Option<String>,
}
impl ModifyEventSubscriptionOutputBuilder {
    /// <p>Detailed information about an event to which you have subscribed.</p>
    pub fn event_subscription(mut self, input: crate::types::EventSubscription) -> Self {
        self.event_subscription = ::std::option::Option::Some(input);
        self
    }
    /// <p>Detailed information about an event to which you have subscribed.</p>
    pub fn set_event_subscription(mut self, input: ::std::option::Option<crate::types::EventSubscription>) -> Self {
        self.event_subscription = input;
        self
    }
    /// <p>Detailed information about an event to which you have subscribed.</p>
    pub fn get_event_subscription(&self) -> &::std::option::Option<crate::types::EventSubscription> {
        &self.event_subscription
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyEventSubscriptionOutput`](crate::operation::modify_event_subscription::ModifyEventSubscriptionOutput).
    pub fn build(self) -> crate::operation::modify_event_subscription::ModifyEventSubscriptionOutput {
        crate::operation::modify_event_subscription::ModifyEventSubscriptionOutput {
            event_subscription: self.event_subscription,
            _request_id: self._request_id,
        }
    }
}
