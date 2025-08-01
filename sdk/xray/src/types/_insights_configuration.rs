// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure containing configurations related to insights.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InsightsConfiguration {
    /// <p>Set the InsightsEnabled value to true to enable insights or false to disable insights.</p>
    pub insights_enabled: ::std::option::Option<bool>,
    /// <p>Set the NotificationsEnabled value to true to enable insights notifications. Notifications can only be enabled on a group with InsightsEnabled set to true.</p>
    pub notifications_enabled: ::std::option::Option<bool>,
}
impl InsightsConfiguration {
    /// <p>Set the InsightsEnabled value to true to enable insights or false to disable insights.</p>
    pub fn insights_enabled(&self) -> ::std::option::Option<bool> {
        self.insights_enabled
    }
    /// <p>Set the NotificationsEnabled value to true to enable insights notifications. Notifications can only be enabled on a group with InsightsEnabled set to true.</p>
    pub fn notifications_enabled(&self) -> ::std::option::Option<bool> {
        self.notifications_enabled
    }
}
impl InsightsConfiguration {
    /// Creates a new builder-style object to manufacture [`InsightsConfiguration`](crate::types::InsightsConfiguration).
    pub fn builder() -> crate::types::builders::InsightsConfigurationBuilder {
        crate::types::builders::InsightsConfigurationBuilder::default()
    }
}

/// A builder for [`InsightsConfiguration`](crate::types::InsightsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InsightsConfigurationBuilder {
    pub(crate) insights_enabled: ::std::option::Option<bool>,
    pub(crate) notifications_enabled: ::std::option::Option<bool>,
}
impl InsightsConfigurationBuilder {
    /// <p>Set the InsightsEnabled value to true to enable insights or false to disable insights.</p>
    pub fn insights_enabled(mut self, input: bool) -> Self {
        self.insights_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set the InsightsEnabled value to true to enable insights or false to disable insights.</p>
    pub fn set_insights_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.insights_enabled = input;
        self
    }
    /// <p>Set the InsightsEnabled value to true to enable insights or false to disable insights.</p>
    pub fn get_insights_enabled(&self) -> &::std::option::Option<bool> {
        &self.insights_enabled
    }
    /// <p>Set the NotificationsEnabled value to true to enable insights notifications. Notifications can only be enabled on a group with InsightsEnabled set to true.</p>
    pub fn notifications_enabled(mut self, input: bool) -> Self {
        self.notifications_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set the NotificationsEnabled value to true to enable insights notifications. Notifications can only be enabled on a group with InsightsEnabled set to true.</p>
    pub fn set_notifications_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.notifications_enabled = input;
        self
    }
    /// <p>Set the NotificationsEnabled value to true to enable insights notifications. Notifications can only be enabled on a group with InsightsEnabled set to true.</p>
    pub fn get_notifications_enabled(&self) -> &::std::option::Option<bool> {
        &self.notifications_enabled
    }
    /// Consumes the builder and constructs a [`InsightsConfiguration`](crate::types::InsightsConfiguration).
    pub fn build(self) -> crate::types::InsightsConfiguration {
        crate::types::InsightsConfiguration {
            insights_enabled: self.insights_enabled,
            notifications_enabled: self.notifications_enabled,
        }
    }
}
