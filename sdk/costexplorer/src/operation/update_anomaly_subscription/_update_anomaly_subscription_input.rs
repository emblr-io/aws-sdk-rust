// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAnomalySubscriptionInput {
    /// <p>A cost anomaly subscription Amazon Resource Name (ARN).</p>
    pub subscription_arn: ::std::option::Option<::std::string::String>,
    /// <p>(deprecated)</p>
    /// <p>The update to the threshold value for receiving notifications.</p>
    /// <p>This field has been deprecated. To update a threshold, use ThresholdExpression. Continued use of Threshold will be treated as shorthand syntax for a ThresholdExpression.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    #[deprecated(note = "Threshold has been deprecated in favor of ThresholdExpression")]
    pub threshold: ::std::option::Option<f64>,
    /// <p>The update to the frequency value that subscribers receive notifications.</p>
    pub frequency: ::std::option::Option<crate::types::AnomalySubscriptionFrequency>,
    /// <p>A list of cost anomaly monitor ARNs.</p>
    pub monitor_arn_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The update to the subscriber list.</p>
    pub subscribers: ::std::option::Option<::std::vec::Vec<crate::types::Subscriber>>,
    /// <p>The new name of the subscription.</p>
    pub subscription_name: ::std::option::Option<::std::string::String>,
    /// <p>The update to the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Expression.html">Expression</a> object used to specify the anomalies that you want to generate alerts for. This supports dimensions and nested expressions. The supported dimensions are <code>ANOMALY_TOTAL_IMPACT_ABSOLUTE</code> and <code>ANOMALY_TOTAL_IMPACT_PERCENTAGE</code>, corresponding to an anomaly’s TotalImpact and TotalImpactPercentage, respectively (see <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Impact.html">Impact</a> for more details). The supported nested expression types are <code>AND</code> and <code>OR</code>. The match option <code>GREATER_THAN_OR_EQUAL</code> is required. Values must be numbers between 0 and 10,000,000,000 in string format.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    /// <p>The following are examples of valid ThresholdExpressions:</p>
    /// <ul>
    /// <li>
    /// <p>Absolute threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p>Percentage threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p><code>AND</code> two thresholds together: <code>{ "And": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// <li>
    /// <p><code>OR</code> two thresholds together: <code>{ "Or": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// </ul>
    pub threshold_expression: ::std::option::Option<crate::types::Expression>,
}
impl UpdateAnomalySubscriptionInput {
    /// <p>A cost anomaly subscription Amazon Resource Name (ARN).</p>
    pub fn subscription_arn(&self) -> ::std::option::Option<&str> {
        self.subscription_arn.as_deref()
    }
    /// <p>(deprecated)</p>
    /// <p>The update to the threshold value for receiving notifications.</p>
    /// <p>This field has been deprecated. To update a threshold, use ThresholdExpression. Continued use of Threshold will be treated as shorthand syntax for a ThresholdExpression.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    #[deprecated(note = "Threshold has been deprecated in favor of ThresholdExpression")]
    pub fn threshold(&self) -> ::std::option::Option<f64> {
        self.threshold
    }
    /// <p>The update to the frequency value that subscribers receive notifications.</p>
    pub fn frequency(&self) -> ::std::option::Option<&crate::types::AnomalySubscriptionFrequency> {
        self.frequency.as_ref()
    }
    /// <p>A list of cost anomaly monitor ARNs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.monitor_arn_list.is_none()`.
    pub fn monitor_arn_list(&self) -> &[::std::string::String] {
        self.monitor_arn_list.as_deref().unwrap_or_default()
    }
    /// <p>The update to the subscriber list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subscribers.is_none()`.
    pub fn subscribers(&self) -> &[crate::types::Subscriber] {
        self.subscribers.as_deref().unwrap_or_default()
    }
    /// <p>The new name of the subscription.</p>
    pub fn subscription_name(&self) -> ::std::option::Option<&str> {
        self.subscription_name.as_deref()
    }
    /// <p>The update to the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Expression.html">Expression</a> object used to specify the anomalies that you want to generate alerts for. This supports dimensions and nested expressions. The supported dimensions are <code>ANOMALY_TOTAL_IMPACT_ABSOLUTE</code> and <code>ANOMALY_TOTAL_IMPACT_PERCENTAGE</code>, corresponding to an anomaly’s TotalImpact and TotalImpactPercentage, respectively (see <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Impact.html">Impact</a> for more details). The supported nested expression types are <code>AND</code> and <code>OR</code>. The match option <code>GREATER_THAN_OR_EQUAL</code> is required. Values must be numbers between 0 and 10,000,000,000 in string format.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    /// <p>The following are examples of valid ThresholdExpressions:</p>
    /// <ul>
    /// <li>
    /// <p>Absolute threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p>Percentage threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p><code>AND</code> two thresholds together: <code>{ "And": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// <li>
    /// <p><code>OR</code> two thresholds together: <code>{ "Or": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// </ul>
    pub fn threshold_expression(&self) -> ::std::option::Option<&crate::types::Expression> {
        self.threshold_expression.as_ref()
    }
}
impl UpdateAnomalySubscriptionInput {
    /// Creates a new builder-style object to manufacture [`UpdateAnomalySubscriptionInput`](crate::operation::update_anomaly_subscription::UpdateAnomalySubscriptionInput).
    pub fn builder() -> crate::operation::update_anomaly_subscription::builders::UpdateAnomalySubscriptionInputBuilder {
        crate::operation::update_anomaly_subscription::builders::UpdateAnomalySubscriptionInputBuilder::default()
    }
}

/// A builder for [`UpdateAnomalySubscriptionInput`](crate::operation::update_anomaly_subscription::UpdateAnomalySubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAnomalySubscriptionInputBuilder {
    pub(crate) subscription_arn: ::std::option::Option<::std::string::String>,
    pub(crate) threshold: ::std::option::Option<f64>,
    pub(crate) frequency: ::std::option::Option<crate::types::AnomalySubscriptionFrequency>,
    pub(crate) monitor_arn_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) subscribers: ::std::option::Option<::std::vec::Vec<crate::types::Subscriber>>,
    pub(crate) subscription_name: ::std::option::Option<::std::string::String>,
    pub(crate) threshold_expression: ::std::option::Option<crate::types::Expression>,
}
impl UpdateAnomalySubscriptionInputBuilder {
    /// <p>A cost anomaly subscription Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn subscription_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A cost anomaly subscription Amazon Resource Name (ARN).</p>
    pub fn set_subscription_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_arn = input;
        self
    }
    /// <p>A cost anomaly subscription Amazon Resource Name (ARN).</p>
    pub fn get_subscription_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_arn
    }
    /// <p>(deprecated)</p>
    /// <p>The update to the threshold value for receiving notifications.</p>
    /// <p>This field has been deprecated. To update a threshold, use ThresholdExpression. Continued use of Threshold will be treated as shorthand syntax for a ThresholdExpression.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    #[deprecated(note = "Threshold has been deprecated in favor of ThresholdExpression")]
    pub fn threshold(mut self, input: f64) -> Self {
        self.threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>(deprecated)</p>
    /// <p>The update to the threshold value for receiving notifications.</p>
    /// <p>This field has been deprecated. To update a threshold, use ThresholdExpression. Continued use of Threshold will be treated as shorthand syntax for a ThresholdExpression.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    #[deprecated(note = "Threshold has been deprecated in favor of ThresholdExpression")]
    pub fn set_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.threshold = input;
        self
    }
    /// <p>(deprecated)</p>
    /// <p>The update to the threshold value for receiving notifications.</p>
    /// <p>This field has been deprecated. To update a threshold, use ThresholdExpression. Continued use of Threshold will be treated as shorthand syntax for a ThresholdExpression.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    #[deprecated(note = "Threshold has been deprecated in favor of ThresholdExpression")]
    pub fn get_threshold(&self) -> &::std::option::Option<f64> {
        &self.threshold
    }
    /// <p>The update to the frequency value that subscribers receive notifications.</p>
    pub fn frequency(mut self, input: crate::types::AnomalySubscriptionFrequency) -> Self {
        self.frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The update to the frequency value that subscribers receive notifications.</p>
    pub fn set_frequency(mut self, input: ::std::option::Option<crate::types::AnomalySubscriptionFrequency>) -> Self {
        self.frequency = input;
        self
    }
    /// <p>The update to the frequency value that subscribers receive notifications.</p>
    pub fn get_frequency(&self) -> &::std::option::Option<crate::types::AnomalySubscriptionFrequency> {
        &self.frequency
    }
    /// Appends an item to `monitor_arn_list`.
    ///
    /// To override the contents of this collection use [`set_monitor_arn_list`](Self::set_monitor_arn_list).
    ///
    /// <p>A list of cost anomaly monitor ARNs.</p>
    pub fn monitor_arn_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.monitor_arn_list.unwrap_or_default();
        v.push(input.into());
        self.monitor_arn_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of cost anomaly monitor ARNs.</p>
    pub fn set_monitor_arn_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.monitor_arn_list = input;
        self
    }
    /// <p>A list of cost anomaly monitor ARNs.</p>
    pub fn get_monitor_arn_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.monitor_arn_list
    }
    /// Appends an item to `subscribers`.
    ///
    /// To override the contents of this collection use [`set_subscribers`](Self::set_subscribers).
    ///
    /// <p>The update to the subscriber list.</p>
    pub fn subscribers(mut self, input: crate::types::Subscriber) -> Self {
        let mut v = self.subscribers.unwrap_or_default();
        v.push(input);
        self.subscribers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The update to the subscriber list.</p>
    pub fn set_subscribers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Subscriber>>) -> Self {
        self.subscribers = input;
        self
    }
    /// <p>The update to the subscriber list.</p>
    pub fn get_subscribers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Subscriber>> {
        &self.subscribers
    }
    /// <p>The new name of the subscription.</p>
    pub fn subscription_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name of the subscription.</p>
    pub fn set_subscription_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_name = input;
        self
    }
    /// <p>The new name of the subscription.</p>
    pub fn get_subscription_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_name
    }
    /// <p>The update to the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Expression.html">Expression</a> object used to specify the anomalies that you want to generate alerts for. This supports dimensions and nested expressions. The supported dimensions are <code>ANOMALY_TOTAL_IMPACT_ABSOLUTE</code> and <code>ANOMALY_TOTAL_IMPACT_PERCENTAGE</code>, corresponding to an anomaly’s TotalImpact and TotalImpactPercentage, respectively (see <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Impact.html">Impact</a> for more details). The supported nested expression types are <code>AND</code> and <code>OR</code>. The match option <code>GREATER_THAN_OR_EQUAL</code> is required. Values must be numbers between 0 and 10,000,000,000 in string format.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    /// <p>The following are examples of valid ThresholdExpressions:</p>
    /// <ul>
    /// <li>
    /// <p>Absolute threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p>Percentage threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p><code>AND</code> two thresholds together: <code>{ "And": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// <li>
    /// <p><code>OR</code> two thresholds together: <code>{ "Or": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// </ul>
    pub fn threshold_expression(mut self, input: crate::types::Expression) -> Self {
        self.threshold_expression = ::std::option::Option::Some(input);
        self
    }
    /// <p>The update to the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Expression.html">Expression</a> object used to specify the anomalies that you want to generate alerts for. This supports dimensions and nested expressions. The supported dimensions are <code>ANOMALY_TOTAL_IMPACT_ABSOLUTE</code> and <code>ANOMALY_TOTAL_IMPACT_PERCENTAGE</code>, corresponding to an anomaly’s TotalImpact and TotalImpactPercentage, respectively (see <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Impact.html">Impact</a> for more details). The supported nested expression types are <code>AND</code> and <code>OR</code>. The match option <code>GREATER_THAN_OR_EQUAL</code> is required. Values must be numbers between 0 and 10,000,000,000 in string format.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    /// <p>The following are examples of valid ThresholdExpressions:</p>
    /// <ul>
    /// <li>
    /// <p>Absolute threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p>Percentage threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p><code>AND</code> two thresholds together: <code>{ "And": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// <li>
    /// <p><code>OR</code> two thresholds together: <code>{ "Or": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// </ul>
    pub fn set_threshold_expression(mut self, input: ::std::option::Option<crate::types::Expression>) -> Self {
        self.threshold_expression = input;
        self
    }
    /// <p>The update to the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Expression.html">Expression</a> object used to specify the anomalies that you want to generate alerts for. This supports dimensions and nested expressions. The supported dimensions are <code>ANOMALY_TOTAL_IMPACT_ABSOLUTE</code> and <code>ANOMALY_TOTAL_IMPACT_PERCENTAGE</code>, corresponding to an anomaly’s TotalImpact and TotalImpactPercentage, respectively (see <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Impact.html">Impact</a> for more details). The supported nested expression types are <code>AND</code> and <code>OR</code>. The match option <code>GREATER_THAN_OR_EQUAL</code> is required. Values must be numbers between 0 and 10,000,000,000 in string format.</p>
    /// <p>You can specify either Threshold or ThresholdExpression, but not both.</p>
    /// <p>The following are examples of valid ThresholdExpressions:</p>
    /// <ul>
    /// <li>
    /// <p>Absolute threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p>Percentage threshold: <code>{ "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }</code></p></li>
    /// <li>
    /// <p><code>AND</code> two thresholds together: <code>{ "And": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// <li>
    /// <p><code>OR</code> two thresholds together: <code>{ "Or": \[ { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } }, { "Dimensions": { "Key": "ANOMALY_TOTAL_IMPACT_PERCENTAGE", "MatchOptions": \[ "GREATER_THAN_OR_EQUAL" \], "Values": \[ "100" \] } } \] }</code></p></li>
    /// </ul>
    pub fn get_threshold_expression(&self) -> &::std::option::Option<crate::types::Expression> {
        &self.threshold_expression
    }
    /// Consumes the builder and constructs a [`UpdateAnomalySubscriptionInput`](crate::operation::update_anomaly_subscription::UpdateAnomalySubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_anomaly_subscription::UpdateAnomalySubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_anomaly_subscription::UpdateAnomalySubscriptionInput {
            subscription_arn: self.subscription_arn,
            threshold: self.threshold,
            frequency: self.frequency,
            monitor_arn_list: self.monitor_arn_list,
            subscribers: self.subscribers,
            subscription_name: self.subscription_name,
            threshold_expression: self.threshold_expression,
        })
    }
}
