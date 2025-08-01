// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The monitoring for an Amazon EC2 instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2LaunchTemplateDataMonitoringDetails {
    /// <p>Enables detailed monitoring when <code>true</code> is specified. Otherwise, basic monitoring is enabled. For more information about detailed monitoring, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html">Enable or turn off detailed monitoring for your instances</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub enabled: ::std::option::Option<bool>,
}
impl AwsEc2LaunchTemplateDataMonitoringDetails {
    /// <p>Enables detailed monitoring when <code>true</code> is specified. Otherwise, basic monitoring is enabled. For more information about detailed monitoring, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html">Enable or turn off detailed monitoring for your instances</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl AwsEc2LaunchTemplateDataMonitoringDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2LaunchTemplateDataMonitoringDetails`](crate::types::AwsEc2LaunchTemplateDataMonitoringDetails).
    pub fn builder() -> crate::types::builders::AwsEc2LaunchTemplateDataMonitoringDetailsBuilder {
        crate::types::builders::AwsEc2LaunchTemplateDataMonitoringDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2LaunchTemplateDataMonitoringDetails`](crate::types::AwsEc2LaunchTemplateDataMonitoringDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2LaunchTemplateDataMonitoringDetailsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl AwsEc2LaunchTemplateDataMonitoringDetailsBuilder {
    /// <p>Enables detailed monitoring when <code>true</code> is specified. Otherwise, basic monitoring is enabled. For more information about detailed monitoring, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html">Enable or turn off detailed monitoring for your instances</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables detailed monitoring when <code>true</code> is specified. Otherwise, basic monitoring is enabled. For more information about detailed monitoring, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html">Enable or turn off detailed monitoring for your instances</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Enables detailed monitoring when <code>true</code> is specified. Otherwise, basic monitoring is enabled. For more information about detailed monitoring, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html">Enable or turn off detailed monitoring for your instances</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`AwsEc2LaunchTemplateDataMonitoringDetails`](crate::types::AwsEc2LaunchTemplateDataMonitoringDetails).
    pub fn build(self) -> crate::types::AwsEc2LaunchTemplateDataMonitoringDetails {
        crate::types::AwsEc2LaunchTemplateDataMonitoringDetails { enabled: self.enabled }
    }
}
