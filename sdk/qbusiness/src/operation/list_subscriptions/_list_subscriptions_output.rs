// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSubscriptionsOutput {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of subscriptions.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of summary information on the subscriptions configured for an Amazon Q Business application.</p>
    pub subscriptions: ::std::option::Option<::std::vec::Vec<crate::types::Subscription>>,
    _request_id: Option<String>,
}
impl ListSubscriptionsOutput {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of subscriptions.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of summary information on the subscriptions configured for an Amazon Q Business application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subscriptions.is_none()`.
    pub fn subscriptions(&self) -> &[crate::types::Subscription] {
        self.subscriptions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSubscriptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSubscriptionsOutput {
    /// Creates a new builder-style object to manufacture [`ListSubscriptionsOutput`](crate::operation::list_subscriptions::ListSubscriptionsOutput).
    pub fn builder() -> crate::operation::list_subscriptions::builders::ListSubscriptionsOutputBuilder {
        crate::operation::list_subscriptions::builders::ListSubscriptionsOutputBuilder::default()
    }
}

/// A builder for [`ListSubscriptionsOutput`](crate::operation::list_subscriptions::ListSubscriptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSubscriptionsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) subscriptions: ::std::option::Option<::std::vec::Vec<crate::types::Subscription>>,
    _request_id: Option<String>,
}
impl ListSubscriptionsOutputBuilder {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of subscriptions.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of subscriptions.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of subscriptions.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `subscriptions`.
    ///
    /// To override the contents of this collection use [`set_subscriptions`](Self::set_subscriptions).
    ///
    /// <p>An array of summary information on the subscriptions configured for an Amazon Q Business application.</p>
    pub fn subscriptions(mut self, input: crate::types::Subscription) -> Self {
        let mut v = self.subscriptions.unwrap_or_default();
        v.push(input);
        self.subscriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of summary information on the subscriptions configured for an Amazon Q Business application.</p>
    pub fn set_subscriptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Subscription>>) -> Self {
        self.subscriptions = input;
        self
    }
    /// <p>An array of summary information on the subscriptions configured for an Amazon Q Business application.</p>
    pub fn get_subscriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Subscription>> {
        &self.subscriptions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSubscriptionsOutput`](crate::operation::list_subscriptions::ListSubscriptionsOutput).
    pub fn build(self) -> crate::operation::list_subscriptions::ListSubscriptionsOutput {
        crate::operation::list_subscriptions::ListSubscriptionsOutput {
            next_token: self.next_token,
            subscriptions: self.subscriptions,
            _request_id: self._request_id,
        }
    }
}
