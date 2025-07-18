// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A notification that's associated with a budget. A budget can have up to ten notifications.</p>
/// <p>Each notification must have at least one subscriber. A notification can have one SNS subscriber and up to 10 email subscribers, for a total of 11 subscribers.</p>
/// <p>For example, if you have a budget for 200 dollars and you want to be notified when you go over 160 dollars, create a notification with the following parameters:</p>
/// <ul>
/// <li>
/// <p>A notificationType of <code>ACTUAL</code></p></li>
/// <li>
/// <p>A <code>thresholdType</code> of <code>PERCENTAGE</code></p></li>
/// <li>
/// <p>A <code>comparisonOperator</code> of <code>GREATER_THAN</code></p></li>
/// <li>
/// <p>A notification <code>threshold</code> of <code>80</code></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Notification {
    /// <p>Specifies whether the notification is for how much you have spent (<code>ACTUAL</code>) or for how much that you're forecasted to spend (<code>FORECASTED</code>).</p>
    pub notification_type: crate::types::NotificationType,
    /// <p>The comparison that's used for this notification.</p>
    pub comparison_operator: crate::types::ComparisonOperator,
    /// <p>The threshold that's associated with a notification. Thresholds are always a percentage, and many customers find value being alerted between 50% - 200% of the budgeted amount. The maximum limit for your threshold is 1,000,000% above the budgeted amount.</p>
    pub threshold: f64,
    /// <p>The type of threshold for a notification. For <code>ABSOLUTE_VALUE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over your total cost threshold. For <code>PERCENTAGE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over a certain percentage of your forecasted spend. For example, if you have a budget for 200 dollars and you have a <code>PERCENTAGE</code> threshold of 80%, Amazon Web Services notifies you when you go over 160 dollars.</p>
    pub threshold_type: ::std::option::Option<crate::types::ThresholdType>,
    /// <p>Specifies whether this notification is in alarm. If a budget notification is in the <code>ALARM</code> state, you passed the set threshold for the budget.</p>
    pub notification_state: ::std::option::Option<crate::types::NotificationState>,
}
impl Notification {
    /// <p>Specifies whether the notification is for how much you have spent (<code>ACTUAL</code>) or for how much that you're forecasted to spend (<code>FORECASTED</code>).</p>
    pub fn notification_type(&self) -> &crate::types::NotificationType {
        &self.notification_type
    }
    /// <p>The comparison that's used for this notification.</p>
    pub fn comparison_operator(&self) -> &crate::types::ComparisonOperator {
        &self.comparison_operator
    }
    /// <p>The threshold that's associated with a notification. Thresholds are always a percentage, and many customers find value being alerted between 50% - 200% of the budgeted amount. The maximum limit for your threshold is 1,000,000% above the budgeted amount.</p>
    pub fn threshold(&self) -> f64 {
        self.threshold
    }
    /// <p>The type of threshold for a notification. For <code>ABSOLUTE_VALUE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over your total cost threshold. For <code>PERCENTAGE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over a certain percentage of your forecasted spend. For example, if you have a budget for 200 dollars and you have a <code>PERCENTAGE</code> threshold of 80%, Amazon Web Services notifies you when you go over 160 dollars.</p>
    pub fn threshold_type(&self) -> ::std::option::Option<&crate::types::ThresholdType> {
        self.threshold_type.as_ref()
    }
    /// <p>Specifies whether this notification is in alarm. If a budget notification is in the <code>ALARM</code> state, you passed the set threshold for the budget.</p>
    pub fn notification_state(&self) -> ::std::option::Option<&crate::types::NotificationState> {
        self.notification_state.as_ref()
    }
}
impl Notification {
    /// Creates a new builder-style object to manufacture [`Notification`](crate::types::Notification).
    pub fn builder() -> crate::types::builders::NotificationBuilder {
        crate::types::builders::NotificationBuilder::default()
    }
}

/// A builder for [`Notification`](crate::types::Notification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotificationBuilder {
    pub(crate) notification_type: ::std::option::Option<crate::types::NotificationType>,
    pub(crate) comparison_operator: ::std::option::Option<crate::types::ComparisonOperator>,
    pub(crate) threshold: ::std::option::Option<f64>,
    pub(crate) threshold_type: ::std::option::Option<crate::types::ThresholdType>,
    pub(crate) notification_state: ::std::option::Option<crate::types::NotificationState>,
}
impl NotificationBuilder {
    /// <p>Specifies whether the notification is for how much you have spent (<code>ACTUAL</code>) or for how much that you're forecasted to spend (<code>FORECASTED</code>).</p>
    /// This field is required.
    pub fn notification_type(mut self, input: crate::types::NotificationType) -> Self {
        self.notification_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the notification is for how much you have spent (<code>ACTUAL</code>) or for how much that you're forecasted to spend (<code>FORECASTED</code>).</p>
    pub fn set_notification_type(mut self, input: ::std::option::Option<crate::types::NotificationType>) -> Self {
        self.notification_type = input;
        self
    }
    /// <p>Specifies whether the notification is for how much you have spent (<code>ACTUAL</code>) or for how much that you're forecasted to spend (<code>FORECASTED</code>).</p>
    pub fn get_notification_type(&self) -> &::std::option::Option<crate::types::NotificationType> {
        &self.notification_type
    }
    /// <p>The comparison that's used for this notification.</p>
    /// This field is required.
    pub fn comparison_operator(mut self, input: crate::types::ComparisonOperator) -> Self {
        self.comparison_operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison that's used for this notification.</p>
    pub fn set_comparison_operator(mut self, input: ::std::option::Option<crate::types::ComparisonOperator>) -> Self {
        self.comparison_operator = input;
        self
    }
    /// <p>The comparison that's used for this notification.</p>
    pub fn get_comparison_operator(&self) -> &::std::option::Option<crate::types::ComparisonOperator> {
        &self.comparison_operator
    }
    /// <p>The threshold that's associated with a notification. Thresholds are always a percentage, and many customers find value being alerted between 50% - 200% of the budgeted amount. The maximum limit for your threshold is 1,000,000% above the budgeted amount.</p>
    /// This field is required.
    pub fn threshold(mut self, input: f64) -> Self {
        self.threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The threshold that's associated with a notification. Thresholds are always a percentage, and many customers find value being alerted between 50% - 200% of the budgeted amount. The maximum limit for your threshold is 1,000,000% above the budgeted amount.</p>
    pub fn set_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.threshold = input;
        self
    }
    /// <p>The threshold that's associated with a notification. Thresholds are always a percentage, and many customers find value being alerted between 50% - 200% of the budgeted amount. The maximum limit for your threshold is 1,000,000% above the budgeted amount.</p>
    pub fn get_threshold(&self) -> &::std::option::Option<f64> {
        &self.threshold
    }
    /// <p>The type of threshold for a notification. For <code>ABSOLUTE_VALUE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over your total cost threshold. For <code>PERCENTAGE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over a certain percentage of your forecasted spend. For example, if you have a budget for 200 dollars and you have a <code>PERCENTAGE</code> threshold of 80%, Amazon Web Services notifies you when you go over 160 dollars.</p>
    pub fn threshold_type(mut self, input: crate::types::ThresholdType) -> Self {
        self.threshold_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of threshold for a notification. For <code>ABSOLUTE_VALUE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over your total cost threshold. For <code>PERCENTAGE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over a certain percentage of your forecasted spend. For example, if you have a budget for 200 dollars and you have a <code>PERCENTAGE</code> threshold of 80%, Amazon Web Services notifies you when you go over 160 dollars.</p>
    pub fn set_threshold_type(mut self, input: ::std::option::Option<crate::types::ThresholdType>) -> Self {
        self.threshold_type = input;
        self
    }
    /// <p>The type of threshold for a notification. For <code>ABSOLUTE_VALUE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over your total cost threshold. For <code>PERCENTAGE</code> thresholds, Amazon Web Services notifies you when you go over or are forecasted to go over a certain percentage of your forecasted spend. For example, if you have a budget for 200 dollars and you have a <code>PERCENTAGE</code> threshold of 80%, Amazon Web Services notifies you when you go over 160 dollars.</p>
    pub fn get_threshold_type(&self) -> &::std::option::Option<crate::types::ThresholdType> {
        &self.threshold_type
    }
    /// <p>Specifies whether this notification is in alarm. If a budget notification is in the <code>ALARM</code> state, you passed the set threshold for the budget.</p>
    pub fn notification_state(mut self, input: crate::types::NotificationState) -> Self {
        self.notification_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this notification is in alarm. If a budget notification is in the <code>ALARM</code> state, you passed the set threshold for the budget.</p>
    pub fn set_notification_state(mut self, input: ::std::option::Option<crate::types::NotificationState>) -> Self {
        self.notification_state = input;
        self
    }
    /// <p>Specifies whether this notification is in alarm. If a budget notification is in the <code>ALARM</code> state, you passed the set threshold for the budget.</p>
    pub fn get_notification_state(&self) -> &::std::option::Option<crate::types::NotificationState> {
        &self.notification_state
    }
    /// Consumes the builder and constructs a [`Notification`](crate::types::Notification).
    /// This method will fail if any of the following fields are not set:
    /// - [`notification_type`](crate::types::builders::NotificationBuilder::notification_type)
    /// - [`comparison_operator`](crate::types::builders::NotificationBuilder::comparison_operator)
    pub fn build(self) -> ::std::result::Result<crate::types::Notification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Notification {
            notification_type: self.notification_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "notification_type",
                    "notification_type was not specified but it is required when building Notification",
                )
            })?,
            comparison_operator: self.comparison_operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparison_operator",
                    "comparison_operator was not specified but it is required when building Notification",
                )
            })?,
            threshold: self.threshold.unwrap_or_default(),
            threshold_type: self.threshold_type,
            notification_state: self.notification_state,
        })
    }
}
