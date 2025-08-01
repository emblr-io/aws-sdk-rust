// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Response for ConfirmSubscriptions action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfirmSubscriptionOutput {
    /// <p>The ARN of the created subscription.</p>
    pub subscription_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ConfirmSubscriptionOutput {
    /// <p>The ARN of the created subscription.</p>
    pub fn subscription_arn(&self) -> ::std::option::Option<&str> {
        self.subscription_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ConfirmSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ConfirmSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`ConfirmSubscriptionOutput`](crate::operation::confirm_subscription::ConfirmSubscriptionOutput).
    pub fn builder() -> crate::operation::confirm_subscription::builders::ConfirmSubscriptionOutputBuilder {
        crate::operation::confirm_subscription::builders::ConfirmSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`ConfirmSubscriptionOutput`](crate::operation::confirm_subscription::ConfirmSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfirmSubscriptionOutputBuilder {
    pub(crate) subscription_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ConfirmSubscriptionOutputBuilder {
    /// <p>The ARN of the created subscription.</p>
    pub fn subscription_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the created subscription.</p>
    pub fn set_subscription_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_arn = input;
        self
    }
    /// <p>The ARN of the created subscription.</p>
    pub fn get_subscription_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ConfirmSubscriptionOutput`](crate::operation::confirm_subscription::ConfirmSubscriptionOutput).
    pub fn build(self) -> crate::operation::confirm_subscription::ConfirmSubscriptionOutput {
        crate::operation::confirm_subscription::ConfirmSubscriptionOutput {
            subscription_arn: self.subscription_arn,
            _request_id: self._request_id,
        }
    }
}
