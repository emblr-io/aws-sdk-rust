// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about one or more notification actions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AlarmNotification {
    /// <p>Contains the notification settings of an alarm model. The settings apply to all alarms that were created based on this alarm model.</p>
    pub notification_actions: ::std::option::Option<::std::vec::Vec<crate::types::NotificationAction>>,
}
impl AlarmNotification {
    /// <p>Contains the notification settings of an alarm model. The settings apply to all alarms that were created based on this alarm model.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notification_actions.is_none()`.
    pub fn notification_actions(&self) -> &[crate::types::NotificationAction] {
        self.notification_actions.as_deref().unwrap_or_default()
    }
}
impl AlarmNotification {
    /// Creates a new builder-style object to manufacture [`AlarmNotification`](crate::types::AlarmNotification).
    pub fn builder() -> crate::types::builders::AlarmNotificationBuilder {
        crate::types::builders::AlarmNotificationBuilder::default()
    }
}

/// A builder for [`AlarmNotification`](crate::types::AlarmNotification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AlarmNotificationBuilder {
    pub(crate) notification_actions: ::std::option::Option<::std::vec::Vec<crate::types::NotificationAction>>,
}
impl AlarmNotificationBuilder {
    /// Appends an item to `notification_actions`.
    ///
    /// To override the contents of this collection use [`set_notification_actions`](Self::set_notification_actions).
    ///
    /// <p>Contains the notification settings of an alarm model. The settings apply to all alarms that were created based on this alarm model.</p>
    pub fn notification_actions(mut self, input: crate::types::NotificationAction) -> Self {
        let mut v = self.notification_actions.unwrap_or_default();
        v.push(input);
        self.notification_actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the notification settings of an alarm model. The settings apply to all alarms that were created based on this alarm model.</p>
    pub fn set_notification_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotificationAction>>) -> Self {
        self.notification_actions = input;
        self
    }
    /// <p>Contains the notification settings of an alarm model. The settings apply to all alarms that were created based on this alarm model.</p>
    pub fn get_notification_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotificationAction>> {
        &self.notification_actions
    }
    /// Consumes the builder and constructs a [`AlarmNotification`](crate::types::AlarmNotification).
    pub fn build(self) -> crate::types::AlarmNotification {
        crate::types::AlarmNotification {
            notification_actions: self.notification_actions,
        }
    }
}
