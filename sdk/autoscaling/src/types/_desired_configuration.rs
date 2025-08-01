// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the desired configuration for an instance refresh.</p>
/// <p>If you specify a desired configuration, you must specify either a <code>LaunchTemplate</code> or a <code>MixedInstancesPolicy</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DesiredConfiguration {
    /// <p>Describes the launch template and the version of the launch template that Amazon EC2 Auto Scaling uses to launch Amazon EC2 instances. For more information about launch templates, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html">Launch templates</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub launch_template: ::std::option::Option<crate::types::LaunchTemplateSpecification>,
    /// <p>Use this structure to launch multiple instance types and On-Demand Instances and Spot Instances within a single Auto Scaling group.</p>
    /// <p>A mixed instances policy contains information that Amazon EC2 Auto Scaling can use to launch instances and help optimize your costs. For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html">Auto Scaling groups with multiple instance types and purchase options</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub mixed_instances_policy: ::std::option::Option<crate::types::MixedInstancesPolicy>,
}
impl DesiredConfiguration {
    /// <p>Describes the launch template and the version of the launch template that Amazon EC2 Auto Scaling uses to launch Amazon EC2 instances. For more information about launch templates, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html">Launch templates</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn launch_template(&self) -> ::std::option::Option<&crate::types::LaunchTemplateSpecification> {
        self.launch_template.as_ref()
    }
    /// <p>Use this structure to launch multiple instance types and On-Demand Instances and Spot Instances within a single Auto Scaling group.</p>
    /// <p>A mixed instances policy contains information that Amazon EC2 Auto Scaling can use to launch instances and help optimize your costs. For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html">Auto Scaling groups with multiple instance types and purchase options</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn mixed_instances_policy(&self) -> ::std::option::Option<&crate::types::MixedInstancesPolicy> {
        self.mixed_instances_policy.as_ref()
    }
}
impl DesiredConfiguration {
    /// Creates a new builder-style object to manufacture [`DesiredConfiguration`](crate::types::DesiredConfiguration).
    pub fn builder() -> crate::types::builders::DesiredConfigurationBuilder {
        crate::types::builders::DesiredConfigurationBuilder::default()
    }
}

/// A builder for [`DesiredConfiguration`](crate::types::DesiredConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DesiredConfigurationBuilder {
    pub(crate) launch_template: ::std::option::Option<crate::types::LaunchTemplateSpecification>,
    pub(crate) mixed_instances_policy: ::std::option::Option<crate::types::MixedInstancesPolicy>,
}
impl DesiredConfigurationBuilder {
    /// <p>Describes the launch template and the version of the launch template that Amazon EC2 Auto Scaling uses to launch Amazon EC2 instances. For more information about launch templates, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html">Launch templates</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn launch_template(mut self, input: crate::types::LaunchTemplateSpecification) -> Self {
        self.launch_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the launch template and the version of the launch template that Amazon EC2 Auto Scaling uses to launch Amazon EC2 instances. For more information about launch templates, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html">Launch templates</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn set_launch_template(mut self, input: ::std::option::Option<crate::types::LaunchTemplateSpecification>) -> Self {
        self.launch_template = input;
        self
    }
    /// <p>Describes the launch template and the version of the launch template that Amazon EC2 Auto Scaling uses to launch Amazon EC2 instances. For more information about launch templates, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-templates.html">Launch templates</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn get_launch_template(&self) -> &::std::option::Option<crate::types::LaunchTemplateSpecification> {
        &self.launch_template
    }
    /// <p>Use this structure to launch multiple instance types and On-Demand Instances and Spot Instances within a single Auto Scaling group.</p>
    /// <p>A mixed instances policy contains information that Amazon EC2 Auto Scaling can use to launch instances and help optimize your costs. For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html">Auto Scaling groups with multiple instance types and purchase options</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn mixed_instances_policy(mut self, input: crate::types::MixedInstancesPolicy) -> Self {
        self.mixed_instances_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this structure to launch multiple instance types and On-Demand Instances and Spot Instances within a single Auto Scaling group.</p>
    /// <p>A mixed instances policy contains information that Amazon EC2 Auto Scaling can use to launch instances and help optimize your costs. For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html">Auto Scaling groups with multiple instance types and purchase options</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn set_mixed_instances_policy(mut self, input: ::std::option::Option<crate::types::MixedInstancesPolicy>) -> Self {
        self.mixed_instances_policy = input;
        self
    }
    /// <p>Use this structure to launch multiple instance types and On-Demand Instances and Spot Instances within a single Auto Scaling group.</p>
    /// <p>A mixed instances policy contains information that Amazon EC2 Auto Scaling can use to launch instances and help optimize your costs. For more information, see <a href="https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html">Auto Scaling groups with multiple instance types and purchase options</a> in the <i>Amazon EC2 Auto Scaling User Guide</i>.</p>
    pub fn get_mixed_instances_policy(&self) -> &::std::option::Option<crate::types::MixedInstancesPolicy> {
        &self.mixed_instances_policy
    }
    /// Consumes the builder and constructs a [`DesiredConfiguration`](crate::types::DesiredConfiguration).
    pub fn build(self) -> crate::types::DesiredConfiguration {
        crate::types::DesiredConfiguration {
            launch_template: self.launch_template,
            mixed_instances_policy: self.mixed_instances_policy,
        }
    }
}
