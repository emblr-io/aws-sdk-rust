// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEventSubscriptionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteEventSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteEventSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteEventSubscriptionOutput`](crate::operation::delete_event_subscription::DeleteEventSubscriptionOutput).
    pub fn builder() -> crate::operation::delete_event_subscription::builders::DeleteEventSubscriptionOutputBuilder {
        crate::operation::delete_event_subscription::builders::DeleteEventSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`DeleteEventSubscriptionOutput`](crate::operation::delete_event_subscription::DeleteEventSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEventSubscriptionOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteEventSubscriptionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteEventSubscriptionOutput`](crate::operation::delete_event_subscription::DeleteEventSubscriptionOutput).
    pub fn build(self) -> crate::operation::delete_event_subscription::DeleteEventSubscriptionOutput {
        crate::operation::delete_event_subscription::DeleteEventSubscriptionOutput {
            _request_id: self._request_id,
        }
    }
}
