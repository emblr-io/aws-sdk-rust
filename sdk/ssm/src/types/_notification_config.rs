// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configurations for sending notifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotificationConfig {
    /// <p>An Amazon Resource Name (ARN) for an Amazon Simple Notification Service (Amazon SNS) topic. Run Command pushes notifications about command status changes to this topic.</p>
    pub notification_arn: ::std::option::Option<::std::string::String>,
    /// <p>The different events for which you can receive notifications. To learn more about these events, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html">Monitoring Systems Manager status changes using Amazon SNS notifications</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub notification_events: ::std::option::Option<::std::vec::Vec<crate::types::NotificationEvent>>,
    /// <p>The type of notification.</p>
    /// <ul>
    /// <li>
    /// <p><code>Command</code>: Receive notification when the status of a command changes.</p></li>
    /// <li>
    /// <p><code>Invocation</code>: For commands sent to multiple managed nodes, receive notification on a per-node basis when the status of a command changes.</p></li>
    /// </ul>
    pub notification_type: ::std::option::Option<crate::types::NotificationType>,
}
impl NotificationConfig {
    /// <p>An Amazon Resource Name (ARN) for an Amazon Simple Notification Service (Amazon SNS) topic. Run Command pushes notifications about command status changes to this topic.</p>
    pub fn notification_arn(&self) -> ::std::option::Option<&str> {
        self.notification_arn.as_deref()
    }
    /// <p>The different events for which you can receive notifications. To learn more about these events, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html">Monitoring Systems Manager status changes using Amazon SNS notifications</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notification_events.is_none()`.
    pub fn notification_events(&self) -> &[crate::types::NotificationEvent] {
        self.notification_events.as_deref().unwrap_or_default()
    }
    /// <p>The type of notification.</p>
    /// <ul>
    /// <li>
    /// <p><code>Command</code>: Receive notification when the status of a command changes.</p></li>
    /// <li>
    /// <p><code>Invocation</code>: For commands sent to multiple managed nodes, receive notification on a per-node basis when the status of a command changes.</p></li>
    /// </ul>
    pub fn notification_type(&self) -> ::std::option::Option<&crate::types::NotificationType> {
        self.notification_type.as_ref()
    }
}
impl NotificationConfig {
    /// Creates a new builder-style object to manufacture [`NotificationConfig`](crate::types::NotificationConfig).
    pub fn builder() -> crate::types::builders::NotificationConfigBuilder {
        crate::types::builders::NotificationConfigBuilder::default()
    }
}

/// A builder for [`NotificationConfig`](crate::types::NotificationConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotificationConfigBuilder {
    pub(crate) notification_arn: ::std::option::Option<::std::string::String>,
    pub(crate) notification_events: ::std::option::Option<::std::vec::Vec<crate::types::NotificationEvent>>,
    pub(crate) notification_type: ::std::option::Option<crate::types::NotificationType>,
}
impl NotificationConfigBuilder {
    /// <p>An Amazon Resource Name (ARN) for an Amazon Simple Notification Service (Amazon SNS) topic. Run Command pushes notifications about command status changes to this topic.</p>
    pub fn notification_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notification_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Resource Name (ARN) for an Amazon Simple Notification Service (Amazon SNS) topic. Run Command pushes notifications about command status changes to this topic.</p>
    pub fn set_notification_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notification_arn = input;
        self
    }
    /// <p>An Amazon Resource Name (ARN) for an Amazon Simple Notification Service (Amazon SNS) topic. Run Command pushes notifications about command status changes to this topic.</p>
    pub fn get_notification_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.notification_arn
    }
    /// Appends an item to `notification_events`.
    ///
    /// To override the contents of this collection use [`set_notification_events`](Self::set_notification_events).
    ///
    /// <p>The different events for which you can receive notifications. To learn more about these events, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html">Monitoring Systems Manager status changes using Amazon SNS notifications</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn notification_events(mut self, input: crate::types::NotificationEvent) -> Self {
        let mut v = self.notification_events.unwrap_or_default();
        v.push(input);
        self.notification_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The different events for which you can receive notifications. To learn more about these events, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html">Monitoring Systems Manager status changes using Amazon SNS notifications</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_notification_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotificationEvent>>) -> Self {
        self.notification_events = input;
        self
    }
    /// <p>The different events for which you can receive notifications. To learn more about these events, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html">Monitoring Systems Manager status changes using Amazon SNS notifications</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_notification_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotificationEvent>> {
        &self.notification_events
    }
    /// <p>The type of notification.</p>
    /// <ul>
    /// <li>
    /// <p><code>Command</code>: Receive notification when the status of a command changes.</p></li>
    /// <li>
    /// <p><code>Invocation</code>: For commands sent to multiple managed nodes, receive notification on a per-node basis when the status of a command changes.</p></li>
    /// </ul>
    pub fn notification_type(mut self, input: crate::types::NotificationType) -> Self {
        self.notification_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of notification.</p>
    /// <ul>
    /// <li>
    /// <p><code>Command</code>: Receive notification when the status of a command changes.</p></li>
    /// <li>
    /// <p><code>Invocation</code>: For commands sent to multiple managed nodes, receive notification on a per-node basis when the status of a command changes.</p></li>
    /// </ul>
    pub fn set_notification_type(mut self, input: ::std::option::Option<crate::types::NotificationType>) -> Self {
        self.notification_type = input;
        self
    }
    /// <p>The type of notification.</p>
    /// <ul>
    /// <li>
    /// <p><code>Command</code>: Receive notification when the status of a command changes.</p></li>
    /// <li>
    /// <p><code>Invocation</code>: For commands sent to multiple managed nodes, receive notification on a per-node basis when the status of a command changes.</p></li>
    /// </ul>
    pub fn get_notification_type(&self) -> &::std::option::Option<crate::types::NotificationType> {
        &self.notification_type
    }
    /// Consumes the builder and constructs a [`NotificationConfig`](crate::types::NotificationConfig).
    pub fn build(self) -> crate::types::NotificationConfig {
        crate::types::NotificationConfig {
            notification_arn: self.notification_arn,
            notification_events: self.notification_events,
            notification_type: self.notification_type,
        }
    }
}
