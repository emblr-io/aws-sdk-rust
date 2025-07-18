// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRumMetricsDestinationInput {
    /// <p>The name of the CloudWatch RUM app monitor that will send the metrics.</p>
    pub app_monitor_name: ::std::option::Option<::std::string::String>,
    /// <p>Defines the destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the ARN of the CloudWatchEvidently experiment that is to be the destination and an IAM role that has permission to write to the experiment.</p>
    pub destination: ::std::option::Option<crate::types::MetricDestination>,
    /// <p>Use this parameter only if <code>Destination</code> is <code>Evidently</code>. This parameter specifies the ARN of the Evidently experiment that will receive the extended metrics.</p>
    pub destination_arn: ::std::option::Option<::std::string::String>,
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, don't use this parameter.</p>
    /// <p>This parameter specifies the ARN of an IAM role that RUM will assume to write to the Evidently experiment that you are sending metrics to. This role must have permission to write to that experiment.</p>
    /// <p>If you specify this parameter, you must be signed on to a role that has <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html">PassRole</a> permissions attached to it, to allow the role to be passed. The <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html#managed-policies-cloudwatch-RUM"> CloudWatchAmazonCloudWatchRUMFullAccess</a> policy doesn't include <code>PassRole</code> permissions.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl PutRumMetricsDestinationInput {
    /// <p>The name of the CloudWatch RUM app monitor that will send the metrics.</p>
    pub fn app_monitor_name(&self) -> ::std::option::Option<&str> {
        self.app_monitor_name.as_deref()
    }
    /// <p>Defines the destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the ARN of the CloudWatchEvidently experiment that is to be the destination and an IAM role that has permission to write to the experiment.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::MetricDestination> {
        self.destination.as_ref()
    }
    /// <p>Use this parameter only if <code>Destination</code> is <code>Evidently</code>. This parameter specifies the ARN of the Evidently experiment that will receive the extended metrics.</p>
    pub fn destination_arn(&self) -> ::std::option::Option<&str> {
        self.destination_arn.as_deref()
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, don't use this parameter.</p>
    /// <p>This parameter specifies the ARN of an IAM role that RUM will assume to write to the Evidently experiment that you are sending metrics to. This role must have permission to write to that experiment.</p>
    /// <p>If you specify this parameter, you must be signed on to a role that has <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html">PassRole</a> permissions attached to it, to allow the role to be passed. The <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html#managed-policies-cloudwatch-RUM"> CloudWatchAmazonCloudWatchRUMFullAccess</a> policy doesn't include <code>PassRole</code> permissions.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
}
impl PutRumMetricsDestinationInput {
    /// Creates a new builder-style object to manufacture [`PutRumMetricsDestinationInput`](crate::operation::put_rum_metrics_destination::PutRumMetricsDestinationInput).
    pub fn builder() -> crate::operation::put_rum_metrics_destination::builders::PutRumMetricsDestinationInputBuilder {
        crate::operation::put_rum_metrics_destination::builders::PutRumMetricsDestinationInputBuilder::default()
    }
}

/// A builder for [`PutRumMetricsDestinationInput`](crate::operation::put_rum_metrics_destination::PutRumMetricsDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRumMetricsDestinationInputBuilder {
    pub(crate) app_monitor_name: ::std::option::Option<::std::string::String>,
    pub(crate) destination: ::std::option::Option<crate::types::MetricDestination>,
    pub(crate) destination_arn: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
}
impl PutRumMetricsDestinationInputBuilder {
    /// <p>The name of the CloudWatch RUM app monitor that will send the metrics.</p>
    /// This field is required.
    pub fn app_monitor_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_monitor_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudWatch RUM app monitor that will send the metrics.</p>
    pub fn set_app_monitor_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_monitor_name = input;
        self
    }
    /// <p>The name of the CloudWatch RUM app monitor that will send the metrics.</p>
    pub fn get_app_monitor_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_monitor_name
    }
    /// <p>Defines the destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the ARN of the CloudWatchEvidently experiment that is to be the destination and an IAM role that has permission to write to the experiment.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::MetricDestination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the ARN of the CloudWatchEvidently experiment that is to be the destination and an IAM role that has permission to write to the experiment.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::MetricDestination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>Defines the destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the ARN of the CloudWatchEvidently experiment that is to be the destination and an IAM role that has permission to write to the experiment.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::MetricDestination> {
        &self.destination
    }
    /// <p>Use this parameter only if <code>Destination</code> is <code>Evidently</code>. This parameter specifies the ARN of the Evidently experiment that will receive the extended metrics.</p>
    pub fn destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this parameter only if <code>Destination</code> is <code>Evidently</code>. This parameter specifies the ARN of the Evidently experiment that will receive the extended metrics.</p>
    pub fn set_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_arn = input;
        self
    }
    /// <p>Use this parameter only if <code>Destination</code> is <code>Evidently</code>. This parameter specifies the ARN of the Evidently experiment that will receive the extended metrics.</p>
    pub fn get_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_arn
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, don't use this parameter.</p>
    /// <p>This parameter specifies the ARN of an IAM role that RUM will assume to write to the Evidently experiment that you are sending metrics to. This role must have permission to write to that experiment.</p>
    /// <p>If you specify this parameter, you must be signed on to a role that has <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html">PassRole</a> permissions attached to it, to allow the role to be passed. The <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html#managed-policies-cloudwatch-RUM"> CloudWatchAmazonCloudWatchRUMFullAccess</a> policy doesn't include <code>PassRole</code> permissions.</p>
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, don't use this parameter.</p>
    /// <p>This parameter specifies the ARN of an IAM role that RUM will assume to write to the Evidently experiment that you are sending metrics to. This role must have permission to write to that experiment.</p>
    /// <p>If you specify this parameter, you must be signed on to a role that has <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html">PassRole</a> permissions attached to it, to allow the role to be passed. The <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html#managed-policies-cloudwatch-RUM"> CloudWatchAmazonCloudWatchRUMFullAccess</a> policy doesn't include <code>PassRole</code> permissions.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, don't use this parameter.</p>
    /// <p>This parameter specifies the ARN of an IAM role that RUM will assume to write to the Evidently experiment that you are sending metrics to. This role must have permission to write to that experiment.</p>
    /// <p>If you specify this parameter, you must be signed on to a role that has <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html">PassRole</a> permissions attached to it, to allow the role to be passed. The <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html#managed-policies-cloudwatch-RUM"> CloudWatchAmazonCloudWatchRUMFullAccess</a> policy doesn't include <code>PassRole</code> permissions.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// Consumes the builder and constructs a [`PutRumMetricsDestinationInput`](crate::operation::put_rum_metrics_destination::PutRumMetricsDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_rum_metrics_destination::PutRumMetricsDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_rum_metrics_destination::PutRumMetricsDestinationInput {
            app_monitor_name: self.app_monitor_name,
            destination: self.destination,
            destination_arn: self.destination_arn,
            iam_role_arn: self.iam_role_arn,
        })
    }
}
