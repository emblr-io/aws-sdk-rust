// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Notification configuration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotificationConfiguration {
    /// Event bridge configuration.
    pub event_bridge_configuration: ::std::option::Option<crate::types::EventBridgeConfiguration>,
}
impl NotificationConfiguration {
    /// Event bridge configuration.
    pub fn event_bridge_configuration(&self) -> ::std::option::Option<&crate::types::EventBridgeConfiguration> {
        self.event_bridge_configuration.as_ref()
    }
}
impl NotificationConfiguration {
    /// Creates a new builder-style object to manufacture [`NotificationConfiguration`](crate::types::NotificationConfiguration).
    pub fn builder() -> crate::types::builders::NotificationConfigurationBuilder {
        crate::types::builders::NotificationConfigurationBuilder::default()
    }
}

/// A builder for [`NotificationConfiguration`](crate::types::NotificationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotificationConfigurationBuilder {
    pub(crate) event_bridge_configuration: ::std::option::Option<crate::types::EventBridgeConfiguration>,
}
impl NotificationConfigurationBuilder {
    /// Event bridge configuration.
    /// This field is required.
    pub fn event_bridge_configuration(mut self, input: crate::types::EventBridgeConfiguration) -> Self {
        self.event_bridge_configuration = ::std::option::Option::Some(input);
        self
    }
    /// Event bridge configuration.
    pub fn set_event_bridge_configuration(mut self, input: ::std::option::Option<crate::types::EventBridgeConfiguration>) -> Self {
        self.event_bridge_configuration = input;
        self
    }
    /// Event bridge configuration.
    pub fn get_event_bridge_configuration(&self) -> &::std::option::Option<crate::types::EventBridgeConfiguration> {
        &self.event_bridge_configuration
    }
    /// Consumes the builder and constructs a [`NotificationConfiguration`](crate::types::NotificationConfiguration).
    pub fn build(self) -> crate::types::NotificationConfiguration {
        crate::types::NotificationConfiguration {
            event_bridge_configuration: self.event_bridge_configuration,
        }
    }
}
