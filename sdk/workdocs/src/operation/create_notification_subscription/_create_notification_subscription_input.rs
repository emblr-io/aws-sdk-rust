// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateNotificationSubscriptionInput {
    /// <p>The ID of the organization.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The endpoint to receive the notifications. If the protocol is HTTPS, the endpoint is a URL that begins with <code>https</code>.</p>
    pub endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The protocol to use. The supported value is https, which delivers JSON-encoded messages using HTTPS POST.</p>
    pub protocol: ::std::option::Option<crate::types::SubscriptionProtocolType>,
    /// <p>The notification type.</p>
    pub subscription_type: ::std::option::Option<crate::types::SubscriptionType>,
}
impl CreateNotificationSubscriptionInput {
    /// <p>The ID of the organization.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The endpoint to receive the notifications. If the protocol is HTTPS, the endpoint is a URL that begins with <code>https</code>.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&str> {
        self.endpoint.as_deref()
    }
    /// <p>The protocol to use. The supported value is https, which delivers JSON-encoded messages using HTTPS POST.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::SubscriptionProtocolType> {
        self.protocol.as_ref()
    }
    /// <p>The notification type.</p>
    pub fn subscription_type(&self) -> ::std::option::Option<&crate::types::SubscriptionType> {
        self.subscription_type.as_ref()
    }
}
impl CreateNotificationSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`CreateNotificationSubscriptionInput`](crate::operation::create_notification_subscription::CreateNotificationSubscriptionInput).
    pub fn builder() -> crate::operation::create_notification_subscription::builders::CreateNotificationSubscriptionInputBuilder {
        crate::operation::create_notification_subscription::builders::CreateNotificationSubscriptionInputBuilder::default()
    }
}

/// A builder for [`CreateNotificationSubscriptionInput`](crate::operation::create_notification_subscription::CreateNotificationSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateNotificationSubscriptionInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) protocol: ::std::option::Option<crate::types::SubscriptionProtocolType>,
    pub(crate) subscription_type: ::std::option::Option<crate::types::SubscriptionType>,
}
impl CreateNotificationSubscriptionInputBuilder {
    /// <p>The ID of the organization.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the organization.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The ID of the organization.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The endpoint to receive the notifications. If the protocol is HTTPS, the endpoint is a URL that begins with <code>https</code>.</p>
    /// This field is required.
    pub fn endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint to receive the notifications. If the protocol is HTTPS, the endpoint is a URL that begins with <code>https</code>.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The endpoint to receive the notifications. If the protocol is HTTPS, the endpoint is a URL that begins with <code>https</code>.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint
    }
    /// <p>The protocol to use. The supported value is https, which delivers JSON-encoded messages using HTTPS POST.</p>
    /// This field is required.
    pub fn protocol(mut self, input: crate::types::SubscriptionProtocolType) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protocol to use. The supported value is https, which delivers JSON-encoded messages using HTTPS POST.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::SubscriptionProtocolType>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol to use. The supported value is https, which delivers JSON-encoded messages using HTTPS POST.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::SubscriptionProtocolType> {
        &self.protocol
    }
    /// <p>The notification type.</p>
    /// This field is required.
    pub fn subscription_type(mut self, input: crate::types::SubscriptionType) -> Self {
        self.subscription_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The notification type.</p>
    pub fn set_subscription_type(mut self, input: ::std::option::Option<crate::types::SubscriptionType>) -> Self {
        self.subscription_type = input;
        self
    }
    /// <p>The notification type.</p>
    pub fn get_subscription_type(&self) -> &::std::option::Option<crate::types::SubscriptionType> {
        &self.subscription_type
    }
    /// Consumes the builder and constructs a [`CreateNotificationSubscriptionInput`](crate::operation::create_notification_subscription::CreateNotificationSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_notification_subscription::CreateNotificationSubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_notification_subscription::CreateNotificationSubscriptionInput {
            organization_id: self.organization_id,
            endpoint: self.endpoint,
            protocol: self.protocol,
            subscription_type: self.subscription_type,
        })
    }
}
