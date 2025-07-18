// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input for ConfirmSubscription action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfirmSubscriptionInput {
    /// <p>The ARN of the topic for which you wish to confirm a subscription.</p>
    pub topic_arn: ::std::option::Option<::std::string::String>,
    /// <p>Short-lived token sent to an endpoint during the <code>Subscribe</code> action.</p>
    pub token: ::std::option::Option<::std::string::String>,
    /// <p>Disallows unauthenticated unsubscribes of the subscription. If the value of this parameter is <code>true</code> and the request has an Amazon Web Services signature, then only the topic owner and the subscription owner can unsubscribe the endpoint. The unsubscribe action requires Amazon Web Services authentication.</p>
    pub authenticate_on_unsubscribe: ::std::option::Option<::std::string::String>,
}
impl ConfirmSubscriptionInput {
    /// <p>The ARN of the topic for which you wish to confirm a subscription.</p>
    pub fn topic_arn(&self) -> ::std::option::Option<&str> {
        self.topic_arn.as_deref()
    }
    /// <p>Short-lived token sent to an endpoint during the <code>Subscribe</code> action.</p>
    pub fn token(&self) -> ::std::option::Option<&str> {
        self.token.as_deref()
    }
    /// <p>Disallows unauthenticated unsubscribes of the subscription. If the value of this parameter is <code>true</code> and the request has an Amazon Web Services signature, then only the topic owner and the subscription owner can unsubscribe the endpoint. The unsubscribe action requires Amazon Web Services authentication.</p>
    pub fn authenticate_on_unsubscribe(&self) -> ::std::option::Option<&str> {
        self.authenticate_on_unsubscribe.as_deref()
    }
}
impl ConfirmSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`ConfirmSubscriptionInput`](crate::operation::confirm_subscription::ConfirmSubscriptionInput).
    pub fn builder() -> crate::operation::confirm_subscription::builders::ConfirmSubscriptionInputBuilder {
        crate::operation::confirm_subscription::builders::ConfirmSubscriptionInputBuilder::default()
    }
}

/// A builder for [`ConfirmSubscriptionInput`](crate::operation::confirm_subscription::ConfirmSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfirmSubscriptionInputBuilder {
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) token: ::std::option::Option<::std::string::String>,
    pub(crate) authenticate_on_unsubscribe: ::std::option::Option<::std::string::String>,
}
impl ConfirmSubscriptionInputBuilder {
    /// <p>The ARN of the topic for which you wish to confirm a subscription.</p>
    /// This field is required.
    pub fn topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the topic for which you wish to confirm a subscription.</p>
    pub fn set_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_arn = input;
        self
    }
    /// <p>The ARN of the topic for which you wish to confirm a subscription.</p>
    pub fn get_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_arn
    }
    /// <p>Short-lived token sent to an endpoint during the <code>Subscribe</code> action.</p>
    /// This field is required.
    pub fn token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Short-lived token sent to an endpoint during the <code>Subscribe</code> action.</p>
    pub fn set_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token = input;
        self
    }
    /// <p>Short-lived token sent to an endpoint during the <code>Subscribe</code> action.</p>
    pub fn get_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.token
    }
    /// <p>Disallows unauthenticated unsubscribes of the subscription. If the value of this parameter is <code>true</code> and the request has an Amazon Web Services signature, then only the topic owner and the subscription owner can unsubscribe the endpoint. The unsubscribe action requires Amazon Web Services authentication.</p>
    pub fn authenticate_on_unsubscribe(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authenticate_on_unsubscribe = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Disallows unauthenticated unsubscribes of the subscription. If the value of this parameter is <code>true</code> and the request has an Amazon Web Services signature, then only the topic owner and the subscription owner can unsubscribe the endpoint. The unsubscribe action requires Amazon Web Services authentication.</p>
    pub fn set_authenticate_on_unsubscribe(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authenticate_on_unsubscribe = input;
        self
    }
    /// <p>Disallows unauthenticated unsubscribes of the subscription. If the value of this parameter is <code>true</code> and the request has an Amazon Web Services signature, then only the topic owner and the subscription owner can unsubscribe the endpoint. The unsubscribe action requires Amazon Web Services authentication.</p>
    pub fn get_authenticate_on_unsubscribe(&self) -> &::std::option::Option<::std::string::String> {
        &self.authenticate_on_unsubscribe
    }
    /// Consumes the builder and constructs a [`ConfirmSubscriptionInput`](crate::operation::confirm_subscription::ConfirmSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::confirm_subscription::ConfirmSubscriptionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::confirm_subscription::ConfirmSubscriptionInput {
            topic_arn: self.topic_arn,
            token: self.token,
            authenticate_on_unsubscribe: self.authenticate_on_unsubscribe,
        })
    }
}
