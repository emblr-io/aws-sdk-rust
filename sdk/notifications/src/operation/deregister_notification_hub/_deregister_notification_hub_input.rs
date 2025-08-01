// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterNotificationHubInput {
    /// <p>The <code>NotificationConfiguration</code> Region.</p>
    pub notification_hub_region: ::std::option::Option<::std::string::String>,
}
impl DeregisterNotificationHubInput {
    /// <p>The <code>NotificationConfiguration</code> Region.</p>
    pub fn notification_hub_region(&self) -> ::std::option::Option<&str> {
        self.notification_hub_region.as_deref()
    }
}
impl DeregisterNotificationHubInput {
    /// Creates a new builder-style object to manufacture [`DeregisterNotificationHubInput`](crate::operation::deregister_notification_hub::DeregisterNotificationHubInput).
    pub fn builder() -> crate::operation::deregister_notification_hub::builders::DeregisterNotificationHubInputBuilder {
        crate::operation::deregister_notification_hub::builders::DeregisterNotificationHubInputBuilder::default()
    }
}

/// A builder for [`DeregisterNotificationHubInput`](crate::operation::deregister_notification_hub::DeregisterNotificationHubInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterNotificationHubInputBuilder {
    pub(crate) notification_hub_region: ::std::option::Option<::std::string::String>,
}
impl DeregisterNotificationHubInputBuilder {
    /// <p>The <code>NotificationConfiguration</code> Region.</p>
    /// This field is required.
    pub fn notification_hub_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notification_hub_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>NotificationConfiguration</code> Region.</p>
    pub fn set_notification_hub_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notification_hub_region = input;
        self
    }
    /// <p>The <code>NotificationConfiguration</code> Region.</p>
    pub fn get_notification_hub_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.notification_hub_region
    }
    /// Consumes the builder and constructs a [`DeregisterNotificationHubInput`](crate::operation::deregister_notification_hub::DeregisterNotificationHubInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::deregister_notification_hub::DeregisterNotificationHubInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::deregister_notification_hub::DeregisterNotificationHubInput {
            notification_hub_region: self.notification_hub_region,
        })
    }
}
