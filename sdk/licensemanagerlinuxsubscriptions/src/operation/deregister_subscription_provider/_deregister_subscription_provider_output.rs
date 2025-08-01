// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterSubscriptionProviderOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeregisterSubscriptionProviderOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeregisterSubscriptionProviderOutput {
    /// Creates a new builder-style object to manufacture [`DeregisterSubscriptionProviderOutput`](crate::operation::deregister_subscription_provider::DeregisterSubscriptionProviderOutput).
    pub fn builder() -> crate::operation::deregister_subscription_provider::builders::DeregisterSubscriptionProviderOutputBuilder {
        crate::operation::deregister_subscription_provider::builders::DeregisterSubscriptionProviderOutputBuilder::default()
    }
}

/// A builder for [`DeregisterSubscriptionProviderOutput`](crate::operation::deregister_subscription_provider::DeregisterSubscriptionProviderOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterSubscriptionProviderOutputBuilder {
    _request_id: Option<String>,
}
impl DeregisterSubscriptionProviderOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeregisterSubscriptionProviderOutput`](crate::operation::deregister_subscription_provider::DeregisterSubscriptionProviderOutput).
    pub fn build(self) -> crate::operation::deregister_subscription_provider::DeregisterSubscriptionProviderOutput {
        crate::operation::deregister_subscription_provider::DeregisterSubscriptionProviderOutput {
            _request_id: self._request_id,
        }
    }
}
