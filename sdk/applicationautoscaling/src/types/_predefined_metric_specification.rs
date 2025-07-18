// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a predefined metric for a target tracking scaling policy to use with Application Auto Scaling.</p>
/// <p>For more information, <a href="https://docs.aws.amazon.com/autoscaling/application/userguide/monitoring-cloudwatch.html#predefined-metrics">Predefined metrics for target tracking scaling policies</a> in the <i>Application Auto Scaling User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PredefinedMetricSpecification {
    /// <p>The metric type. The <code>ALBRequestCountPerTarget</code> metric type applies only to Spot Fleets and ECS services.</p>
    pub predefined_metric_type: crate::types::MetricType,
    /// <p>Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is <code>ALBRequestCountPerTarget</code> and there is a target group attached to the Spot Fleet or ECS service.</p>
    /// <p>You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:</p>
    /// <p><code>app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff</code>.</p>
    /// <p>Where:</p>
    /// <ul>
    /// <li>
    /// <p>app/<load-balancer-name>
    /// /
    /// <load-balancer-id>
    /// is the final portion of the load balancer ARN
    /// </load-balancer-id>
    /// </load-balancer-name></p></li>
    /// <li>
    /// <p>targetgroup/<target-group-name>
    /// /
    /// <target-group-id>
    /// is the final portion of the target group ARN.
    /// </target-group-id>
    /// </target-group-name></p></li>
    /// </ul>
    /// <p>To find the ARN for an Application Load Balancer, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html">DescribeLoadBalancers</a> API operation. To find the ARN for the target group, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html">DescribeTargetGroups</a> API operation.</p>
    pub resource_label: ::std::option::Option<::std::string::String>,
}
impl PredefinedMetricSpecification {
    /// <p>The metric type. The <code>ALBRequestCountPerTarget</code> metric type applies only to Spot Fleets and ECS services.</p>
    pub fn predefined_metric_type(&self) -> &crate::types::MetricType {
        &self.predefined_metric_type
    }
    /// <p>Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is <code>ALBRequestCountPerTarget</code> and there is a target group attached to the Spot Fleet or ECS service.</p>
    /// <p>You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:</p>
    /// <p><code>app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff</code>.</p>
    /// <p>Where:</p>
    /// <ul>
    /// <li>
    /// <p>app/<load-balancer-name>
    /// /
    /// <load-balancer-id>
    /// is the final portion of the load balancer ARN
    /// </load-balancer-id>
    /// </load-balancer-name></p></li>
    /// <li>
    /// <p>targetgroup/<target-group-name>
    /// /
    /// <target-group-id>
    /// is the final portion of the target group ARN.
    /// </target-group-id>
    /// </target-group-name></p></li>
    /// </ul>
    /// <p>To find the ARN for an Application Load Balancer, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html">DescribeLoadBalancers</a> API operation. To find the ARN for the target group, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html">DescribeTargetGroups</a> API operation.</p>
    pub fn resource_label(&self) -> ::std::option::Option<&str> {
        self.resource_label.as_deref()
    }
}
impl PredefinedMetricSpecification {
    /// Creates a new builder-style object to manufacture [`PredefinedMetricSpecification`](crate::types::PredefinedMetricSpecification).
    pub fn builder() -> crate::types::builders::PredefinedMetricSpecificationBuilder {
        crate::types::builders::PredefinedMetricSpecificationBuilder::default()
    }
}

/// A builder for [`PredefinedMetricSpecification`](crate::types::PredefinedMetricSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PredefinedMetricSpecificationBuilder {
    pub(crate) predefined_metric_type: ::std::option::Option<crate::types::MetricType>,
    pub(crate) resource_label: ::std::option::Option<::std::string::String>,
}
impl PredefinedMetricSpecificationBuilder {
    /// <p>The metric type. The <code>ALBRequestCountPerTarget</code> metric type applies only to Spot Fleets and ECS services.</p>
    /// This field is required.
    pub fn predefined_metric_type(mut self, input: crate::types::MetricType) -> Self {
        self.predefined_metric_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric type. The <code>ALBRequestCountPerTarget</code> metric type applies only to Spot Fleets and ECS services.</p>
    pub fn set_predefined_metric_type(mut self, input: ::std::option::Option<crate::types::MetricType>) -> Self {
        self.predefined_metric_type = input;
        self
    }
    /// <p>The metric type. The <code>ALBRequestCountPerTarget</code> metric type applies only to Spot Fleets and ECS services.</p>
    pub fn get_predefined_metric_type(&self) -> &::std::option::Option<crate::types::MetricType> {
        &self.predefined_metric_type
    }
    /// <p>Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is <code>ALBRequestCountPerTarget</code> and there is a target group attached to the Spot Fleet or ECS service.</p>
    /// <p>You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:</p>
    /// <p><code>app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff</code>.</p>
    /// <p>Where:</p>
    /// <ul>
    /// <li>
    /// <p>app/<load-balancer-name>
    /// /
    /// <load-balancer-id>
    /// is the final portion of the load balancer ARN
    /// </load-balancer-id>
    /// </load-balancer-name></p></li>
    /// <li>
    /// <p>targetgroup/<target-group-name>
    /// /
    /// <target-group-id>
    /// is the final portion of the target group ARN.
    /// </target-group-id>
    /// </target-group-name></p></li>
    /// </ul>
    /// <p>To find the ARN for an Application Load Balancer, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html">DescribeLoadBalancers</a> API operation. To find the ARN for the target group, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html">DescribeTargetGroups</a> API operation.</p>
    pub fn resource_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is <code>ALBRequestCountPerTarget</code> and there is a target group attached to the Spot Fleet or ECS service.</p>
    /// <p>You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:</p>
    /// <p><code>app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff</code>.</p>
    /// <p>Where:</p>
    /// <ul>
    /// <li>
    /// <p>app/<load-balancer-name>
    /// /
    /// <load-balancer-id>
    /// is the final portion of the load balancer ARN
    /// </load-balancer-id>
    /// </load-balancer-name></p></li>
    /// <li>
    /// <p>targetgroup/<target-group-name>
    /// /
    /// <target-group-id>
    /// is the final portion of the target group ARN.
    /// </target-group-id>
    /// </target-group-name></p></li>
    /// </ul>
    /// <p>To find the ARN for an Application Load Balancer, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html">DescribeLoadBalancers</a> API operation. To find the ARN for the target group, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html">DescribeTargetGroups</a> API operation.</p>
    pub fn set_resource_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_label = input;
        self
    }
    /// <p>Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is <code>ALBRequestCountPerTarget</code> and there is a target group attached to the Spot Fleet or ECS service.</p>
    /// <p>You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:</p>
    /// <p><code>app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff</code>.</p>
    /// <p>Where:</p>
    /// <ul>
    /// <li>
    /// <p>app/<load-balancer-name>
    /// /
    /// <load-balancer-id>
    /// is the final portion of the load balancer ARN
    /// </load-balancer-id>
    /// </load-balancer-name></p></li>
    /// <li>
    /// <p>targetgroup/<target-group-name>
    /// /
    /// <target-group-id>
    /// is the final portion of the target group ARN.
    /// </target-group-id>
    /// </target-group-name></p></li>
    /// </ul>
    /// <p>To find the ARN for an Application Load Balancer, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html">DescribeLoadBalancers</a> API operation. To find the ARN for the target group, use the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html">DescribeTargetGroups</a> API operation.</p>
    pub fn get_resource_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_label
    }
    /// Consumes the builder and constructs a [`PredefinedMetricSpecification`](crate::types::PredefinedMetricSpecification).
    /// This method will fail if any of the following fields are not set:
    /// - [`predefined_metric_type`](crate::types::builders::PredefinedMetricSpecificationBuilder::predefined_metric_type)
    pub fn build(self) -> ::std::result::Result<crate::types::PredefinedMetricSpecification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PredefinedMetricSpecification {
            predefined_metric_type: self.predefined_metric_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "predefined_metric_type",
                    "predefined_metric_type was not specified but it is required when building PredefinedMetricSpecification",
                )
            })?,
            resource_label: self.resource_label,
        })
    }
}
