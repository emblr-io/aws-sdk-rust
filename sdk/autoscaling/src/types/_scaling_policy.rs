// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a scaling policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScalingPolicy {
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the scaling policy.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the policy.</p>
    pub policy_arn: ::std::option::Option<::std::string::String>,
    /// <p>One of the following policy types:</p>
    /// <ul>
    /// <li>
    /// <p><code>TargetTrackingScaling</code></p></li>
    /// <li>
    /// <p><code>StepScaling</code></p></li>
    /// <li>
    /// <p><code>SimpleScaling</code> (default)</p></li>
    /// <li>
    /// <p><code>PredictiveScaling</code></p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html">Target tracking scaling policies</a> and <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html">Step and simple scaling policies</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub policy_type: ::std::option::Option<::std::string::String>,
    /// <p>Specifies how the scaling adjustment is interpreted (for example, an absolute number or a percentage). The valid values are <code>ChangeInCapacity</code>, <code>ExactCapacity</code>, and <code>PercentChangeInCapacity</code>.</p>
    pub adjustment_type: ::std::option::Option<::std::string::String>,
    /// <p>Available for backward compatibility. Use <code>MinAdjustmentMagnitude</code> instead.</p>
    pub min_adjustment_step: ::std::option::Option<i32>,
    /// <p>The minimum value to scale by when the adjustment type is <code>PercentChangeInCapacity</code>.</p>
    pub min_adjustment_magnitude: ::std::option::Option<i32>,
    /// <p>The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity.</p>
    pub scaling_adjustment: ::std::option::Option<i32>,
    /// <p>The duration of the policy's cooldown period, in seconds.</p>
    pub cooldown: ::std::option::Option<i32>,
    /// <p>A set of adjustments that enable you to scale based on the size of the alarm breach.</p>
    pub step_adjustments: ::std::option::Option<::std::vec::Vec<crate::types::StepAdjustment>>,
    /// <p>The aggregation type for the CloudWatch metrics. The valid values are <code>Minimum</code>, <code>Maximum</code>, and <code>Average</code>.</p>
    pub metric_aggregation_type: ::std::option::Option<::std::string::String>,
    /// <p>The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.</p>
    pub estimated_instance_warmup: ::std::option::Option<i32>,
    /// <p>The CloudWatch alarms related to the policy.</p>
    pub alarms: ::std::option::Option<::std::vec::Vec<crate::types::Alarm>>,
    /// <p>A target tracking scaling policy.</p>
    pub target_tracking_configuration: ::std::option::Option<crate::types::TargetTrackingConfiguration>,
    /// <p>Indicates whether the policy is enabled (<code>true</code>) or disabled (<code>false</code>).</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>A predictive scaling policy.</p>
    pub predictive_scaling_configuration: ::std::option::Option<crate::types::PredictiveScalingConfiguration>,
}
impl ScalingPolicy {
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
    /// <p>The name of the scaling policy.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the policy.</p>
    pub fn policy_arn(&self) -> ::std::option::Option<&str> {
        self.policy_arn.as_deref()
    }
    /// <p>One of the following policy types:</p>
    /// <ul>
    /// <li>
    /// <p><code>TargetTrackingScaling</code></p></li>
    /// <li>
    /// <p><code>StepScaling</code></p></li>
    /// <li>
    /// <p><code>SimpleScaling</code> (default)</p></li>
    /// <li>
    /// <p><code>PredictiveScaling</code></p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html">Target tracking scaling policies</a> and <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html">Step and simple scaling policies</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn policy_type(&self) -> ::std::option::Option<&str> {
        self.policy_type.as_deref()
    }
    /// <p>Specifies how the scaling adjustment is interpreted (for example, an absolute number or a percentage). The valid values are <code>ChangeInCapacity</code>, <code>ExactCapacity</code>, and <code>PercentChangeInCapacity</code>.</p>
    pub fn adjustment_type(&self) -> ::std::option::Option<&str> {
        self.adjustment_type.as_deref()
    }
    /// <p>Available for backward compatibility. Use <code>MinAdjustmentMagnitude</code> instead.</p>
    pub fn min_adjustment_step(&self) -> ::std::option::Option<i32> {
        self.min_adjustment_step
    }
    /// <p>The minimum value to scale by when the adjustment type is <code>PercentChangeInCapacity</code>.</p>
    pub fn min_adjustment_magnitude(&self) -> ::std::option::Option<i32> {
        self.min_adjustment_magnitude
    }
    /// <p>The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity.</p>
    pub fn scaling_adjustment(&self) -> ::std::option::Option<i32> {
        self.scaling_adjustment
    }
    /// <p>The duration of the policy's cooldown period, in seconds.</p>
    pub fn cooldown(&self) -> ::std::option::Option<i32> {
        self.cooldown
    }
    /// <p>A set of adjustments that enable you to scale based on the size of the alarm breach.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.step_adjustments.is_none()`.
    pub fn step_adjustments(&self) -> &[crate::types::StepAdjustment] {
        self.step_adjustments.as_deref().unwrap_or_default()
    }
    /// <p>The aggregation type for the CloudWatch metrics. The valid values are <code>Minimum</code>, <code>Maximum</code>, and <code>Average</code>.</p>
    pub fn metric_aggregation_type(&self) -> ::std::option::Option<&str> {
        self.metric_aggregation_type.as_deref()
    }
    /// <p>The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.</p>
    pub fn estimated_instance_warmup(&self) -> ::std::option::Option<i32> {
        self.estimated_instance_warmup
    }
    /// <p>The CloudWatch alarms related to the policy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.alarms.is_none()`.
    pub fn alarms(&self) -> &[crate::types::Alarm] {
        self.alarms.as_deref().unwrap_or_default()
    }
    /// <p>A target tracking scaling policy.</p>
    pub fn target_tracking_configuration(&self) -> ::std::option::Option<&crate::types::TargetTrackingConfiguration> {
        self.target_tracking_configuration.as_ref()
    }
    /// <p>Indicates whether the policy is enabled (<code>true</code>) or disabled (<code>false</code>).</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>A predictive scaling policy.</p>
    pub fn predictive_scaling_configuration(&self) -> ::std::option::Option<&crate::types::PredictiveScalingConfiguration> {
        self.predictive_scaling_configuration.as_ref()
    }
}
impl ScalingPolicy {
    /// Creates a new builder-style object to manufacture [`ScalingPolicy`](crate::types::ScalingPolicy).
    pub fn builder() -> crate::types::builders::ScalingPolicyBuilder {
        crate::types::builders::ScalingPolicyBuilder::default()
    }
}

/// A builder for [`ScalingPolicy`](crate::types::ScalingPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScalingPolicyBuilder {
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy_arn: ::std::option::Option<::std::string::String>,
    pub(crate) policy_type: ::std::option::Option<::std::string::String>,
    pub(crate) adjustment_type: ::std::option::Option<::std::string::String>,
    pub(crate) min_adjustment_step: ::std::option::Option<i32>,
    pub(crate) min_adjustment_magnitude: ::std::option::Option<i32>,
    pub(crate) scaling_adjustment: ::std::option::Option<i32>,
    pub(crate) cooldown: ::std::option::Option<i32>,
    pub(crate) step_adjustments: ::std::option::Option<::std::vec::Vec<crate::types::StepAdjustment>>,
    pub(crate) metric_aggregation_type: ::std::option::Option<::std::string::String>,
    pub(crate) estimated_instance_warmup: ::std::option::Option<i32>,
    pub(crate) alarms: ::std::option::Option<::std::vec::Vec<crate::types::Alarm>>,
    pub(crate) target_tracking_configuration: ::std::option::Option<crate::types::TargetTrackingConfiguration>,
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) predictive_scaling_configuration: ::std::option::Option<crate::types::PredictiveScalingConfiguration>,
}
impl ScalingPolicyBuilder {
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn set_auto_scaling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_name = input;
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn get_auto_scaling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_name
    }
    /// <p>The name of the scaling policy.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the scaling policy.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the scaling policy.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>The Amazon Resource Name (ARN) of the policy.</p>
    pub fn policy_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the policy.</p>
    pub fn set_policy_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the policy.</p>
    pub fn get_policy_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_arn
    }
    /// <p>One of the following policy types:</p>
    /// <ul>
    /// <li>
    /// <p><code>TargetTrackingScaling</code></p></li>
    /// <li>
    /// <p><code>StepScaling</code></p></li>
    /// <li>
    /// <p><code>SimpleScaling</code> (default)</p></li>
    /// <li>
    /// <p><code>PredictiveScaling</code></p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html">Target tracking scaling policies</a> and <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html">Step and simple scaling policies</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn policy_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>One of the following policy types:</p>
    /// <ul>
    /// <li>
    /// <p><code>TargetTrackingScaling</code></p></li>
    /// <li>
    /// <p><code>StepScaling</code></p></li>
    /// <li>
    /// <p><code>SimpleScaling</code> (default)</p></li>
    /// <li>
    /// <p><code>PredictiveScaling</code></p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html">Target tracking scaling policies</a> and <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html">Step and simple scaling policies</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn set_policy_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_type = input;
        self
    }
    /// <p>One of the following policy types:</p>
    /// <ul>
    /// <li>
    /// <p><code>TargetTrackingScaling</code></p></li>
    /// <li>
    /// <p><code>StepScaling</code></p></li>
    /// <li>
    /// <p><code>SimpleScaling</code> (default)</p></li>
    /// <li>
    /// <p><code>PredictiveScaling</code></p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html">Target tracking scaling policies</a> and <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html">Step and simple scaling policies</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn get_policy_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_type
    }
    /// <p>Specifies how the scaling adjustment is interpreted (for example, an absolute number or a percentage). The valid values are <code>ChangeInCapacity</code>, <code>ExactCapacity</code>, and <code>PercentChangeInCapacity</code>.</p>
    pub fn adjustment_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adjustment_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies how the scaling adjustment is interpreted (for example, an absolute number or a percentage). The valid values are <code>ChangeInCapacity</code>, <code>ExactCapacity</code>, and <code>PercentChangeInCapacity</code>.</p>
    pub fn set_adjustment_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adjustment_type = input;
        self
    }
    /// <p>Specifies how the scaling adjustment is interpreted (for example, an absolute number or a percentage). The valid values are <code>ChangeInCapacity</code>, <code>ExactCapacity</code>, and <code>PercentChangeInCapacity</code>.</p>
    pub fn get_adjustment_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.adjustment_type
    }
    /// <p>Available for backward compatibility. Use <code>MinAdjustmentMagnitude</code> instead.</p>
    pub fn min_adjustment_step(mut self, input: i32) -> Self {
        self.min_adjustment_step = ::std::option::Option::Some(input);
        self
    }
    /// <p>Available for backward compatibility. Use <code>MinAdjustmentMagnitude</code> instead.</p>
    pub fn set_min_adjustment_step(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_adjustment_step = input;
        self
    }
    /// <p>Available for backward compatibility. Use <code>MinAdjustmentMagnitude</code> instead.</p>
    pub fn get_min_adjustment_step(&self) -> &::std::option::Option<i32> {
        &self.min_adjustment_step
    }
    /// <p>The minimum value to scale by when the adjustment type is <code>PercentChangeInCapacity</code>.</p>
    pub fn min_adjustment_magnitude(mut self, input: i32) -> Self {
        self.min_adjustment_magnitude = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum value to scale by when the adjustment type is <code>PercentChangeInCapacity</code>.</p>
    pub fn set_min_adjustment_magnitude(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_adjustment_magnitude = input;
        self
    }
    /// <p>The minimum value to scale by when the adjustment type is <code>PercentChangeInCapacity</code>.</p>
    pub fn get_min_adjustment_magnitude(&self) -> &::std::option::Option<i32> {
        &self.min_adjustment_magnitude
    }
    /// <p>The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity.</p>
    pub fn scaling_adjustment(mut self, input: i32) -> Self {
        self.scaling_adjustment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity.</p>
    pub fn set_scaling_adjustment(mut self, input: ::std::option::Option<i32>) -> Self {
        self.scaling_adjustment = input;
        self
    }
    /// <p>The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity.</p>
    pub fn get_scaling_adjustment(&self) -> &::std::option::Option<i32> {
        &self.scaling_adjustment
    }
    /// <p>The duration of the policy's cooldown period, in seconds.</p>
    pub fn cooldown(mut self, input: i32) -> Self {
        self.cooldown = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration of the policy's cooldown period, in seconds.</p>
    pub fn set_cooldown(mut self, input: ::std::option::Option<i32>) -> Self {
        self.cooldown = input;
        self
    }
    /// <p>The duration of the policy's cooldown period, in seconds.</p>
    pub fn get_cooldown(&self) -> &::std::option::Option<i32> {
        &self.cooldown
    }
    /// Appends an item to `step_adjustments`.
    ///
    /// To override the contents of this collection use [`set_step_adjustments`](Self::set_step_adjustments).
    ///
    /// <p>A set of adjustments that enable you to scale based on the size of the alarm breach.</p>
    pub fn step_adjustments(mut self, input: crate::types::StepAdjustment) -> Self {
        let mut v = self.step_adjustments.unwrap_or_default();
        v.push(input);
        self.step_adjustments = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of adjustments that enable you to scale based on the size of the alarm breach.</p>
    pub fn set_step_adjustments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StepAdjustment>>) -> Self {
        self.step_adjustments = input;
        self
    }
    /// <p>A set of adjustments that enable you to scale based on the size of the alarm breach.</p>
    pub fn get_step_adjustments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StepAdjustment>> {
        &self.step_adjustments
    }
    /// <p>The aggregation type for the CloudWatch metrics. The valid values are <code>Minimum</code>, <code>Maximum</code>, and <code>Average</code>.</p>
    pub fn metric_aggregation_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_aggregation_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The aggregation type for the CloudWatch metrics. The valid values are <code>Minimum</code>, <code>Maximum</code>, and <code>Average</code>.</p>
    pub fn set_metric_aggregation_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_aggregation_type = input;
        self
    }
    /// <p>The aggregation type for the CloudWatch metrics. The valid values are <code>Minimum</code>, <code>Maximum</code>, and <code>Average</code>.</p>
    pub fn get_metric_aggregation_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_aggregation_type
    }
    /// <p>The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.</p>
    pub fn estimated_instance_warmup(mut self, input: i32) -> Self {
        self.estimated_instance_warmup = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.</p>
    pub fn set_estimated_instance_warmup(mut self, input: ::std::option::Option<i32>) -> Self {
        self.estimated_instance_warmup = input;
        self
    }
    /// <p>The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.</p>
    pub fn get_estimated_instance_warmup(&self) -> &::std::option::Option<i32> {
        &self.estimated_instance_warmup
    }
    /// Appends an item to `alarms`.
    ///
    /// To override the contents of this collection use [`set_alarms`](Self::set_alarms).
    ///
    /// <p>The CloudWatch alarms related to the policy.</p>
    pub fn alarms(mut self, input: crate::types::Alarm) -> Self {
        let mut v = self.alarms.unwrap_or_default();
        v.push(input);
        self.alarms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The CloudWatch alarms related to the policy.</p>
    pub fn set_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Alarm>>) -> Self {
        self.alarms = input;
        self
    }
    /// <p>The CloudWatch alarms related to the policy.</p>
    pub fn get_alarms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Alarm>> {
        &self.alarms
    }
    /// <p>A target tracking scaling policy.</p>
    pub fn target_tracking_configuration(mut self, input: crate::types::TargetTrackingConfiguration) -> Self {
        self.target_tracking_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A target tracking scaling policy.</p>
    pub fn set_target_tracking_configuration(mut self, input: ::std::option::Option<crate::types::TargetTrackingConfiguration>) -> Self {
        self.target_tracking_configuration = input;
        self
    }
    /// <p>A target tracking scaling policy.</p>
    pub fn get_target_tracking_configuration(&self) -> &::std::option::Option<crate::types::TargetTrackingConfiguration> {
        &self.target_tracking_configuration
    }
    /// <p>Indicates whether the policy is enabled (<code>true</code>) or disabled (<code>false</code>).</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the policy is enabled (<code>true</code>) or disabled (<code>false</code>).</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Indicates whether the policy is enabled (<code>true</code>) or disabled (<code>false</code>).</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>A predictive scaling policy.</p>
    pub fn predictive_scaling_configuration(mut self, input: crate::types::PredictiveScalingConfiguration) -> Self {
        self.predictive_scaling_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A predictive scaling policy.</p>
    pub fn set_predictive_scaling_configuration(mut self, input: ::std::option::Option<crate::types::PredictiveScalingConfiguration>) -> Self {
        self.predictive_scaling_configuration = input;
        self
    }
    /// <p>A predictive scaling policy.</p>
    pub fn get_predictive_scaling_configuration(&self) -> &::std::option::Option<crate::types::PredictiveScalingConfiguration> {
        &self.predictive_scaling_configuration
    }
    /// Consumes the builder and constructs a [`ScalingPolicy`](crate::types::ScalingPolicy).
    pub fn build(self) -> crate::types::ScalingPolicy {
        crate::types::ScalingPolicy {
            auto_scaling_group_name: self.auto_scaling_group_name,
            policy_name: self.policy_name,
            policy_arn: self.policy_arn,
            policy_type: self.policy_type,
            adjustment_type: self.adjustment_type,
            min_adjustment_step: self.min_adjustment_step,
            min_adjustment_magnitude: self.min_adjustment_magnitude,
            scaling_adjustment: self.scaling_adjustment,
            cooldown: self.cooldown,
            step_adjustments: self.step_adjustments,
            metric_aggregation_type: self.metric_aggregation_type,
            estimated_instance_warmup: self.estimated_instance_warmup,
            alarms: self.alarms,
            target_tracking_configuration: self.target_tracking_configuration,
            enabled: self.enabled,
            predictive_scaling_configuration: self.predictive_scaling_configuration,
        }
    }
}
