// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateRumMetricDefinitionsInput {
    /// <p>The name of the CloudWatch RUM app monitor that is to send the metrics.</p>
    pub app_monitor_name: ::std::option::Option<::std::string::String>,
    /// <p>The destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the Amazon Resource Name (ARN) of the CloudWatchEvidently experiment that will receive the metrics and an IAM role that has permission to write to the experiment.</p>
    pub destination: ::std::option::Option<crate::types::MetricDestination>,
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, do not use this parameter.</p>
    /// <p>This parameter specifies the ARN of the Evidently experiment that is to receive the metrics. You must have already defined this experiment as a valid destination. For more information, see <a href="https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_PutRumMetricsDestination.html">PutRumMetricsDestination</a>.</p>
    pub destination_arn: ::std::option::Option<::std::string::String>,
    /// <p>An array of structures which define the metrics that you want to send.</p>
    pub metric_definitions: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinitionRequest>>,
}
impl BatchCreateRumMetricDefinitionsInput {
    /// <p>The name of the CloudWatch RUM app monitor that is to send the metrics.</p>
    pub fn app_monitor_name(&self) -> ::std::option::Option<&str> {
        self.app_monitor_name.as_deref()
    }
    /// <p>The destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the Amazon Resource Name (ARN) of the CloudWatchEvidently experiment that will receive the metrics and an IAM role that has permission to write to the experiment.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::MetricDestination> {
        self.destination.as_ref()
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, do not use this parameter.</p>
    /// <p>This parameter specifies the ARN of the Evidently experiment that is to receive the metrics. You must have already defined this experiment as a valid destination. For more information, see <a href="https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_PutRumMetricsDestination.html">PutRumMetricsDestination</a>.</p>
    pub fn destination_arn(&self) -> ::std::option::Option<&str> {
        self.destination_arn.as_deref()
    }
    /// <p>An array of structures which define the metrics that you want to send.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_definitions.is_none()`.
    pub fn metric_definitions(&self) -> &[crate::types::MetricDefinitionRequest] {
        self.metric_definitions.as_deref().unwrap_or_default()
    }
}
impl BatchCreateRumMetricDefinitionsInput {
    /// Creates a new builder-style object to manufacture [`BatchCreateRumMetricDefinitionsInput`](crate::operation::batch_create_rum_metric_definitions::BatchCreateRumMetricDefinitionsInput).
    pub fn builder() -> crate::operation::batch_create_rum_metric_definitions::builders::BatchCreateRumMetricDefinitionsInputBuilder {
        crate::operation::batch_create_rum_metric_definitions::builders::BatchCreateRumMetricDefinitionsInputBuilder::default()
    }
}

/// A builder for [`BatchCreateRumMetricDefinitionsInput`](crate::operation::batch_create_rum_metric_definitions::BatchCreateRumMetricDefinitionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateRumMetricDefinitionsInputBuilder {
    pub(crate) app_monitor_name: ::std::option::Option<::std::string::String>,
    pub(crate) destination: ::std::option::Option<crate::types::MetricDestination>,
    pub(crate) destination_arn: ::std::option::Option<::std::string::String>,
    pub(crate) metric_definitions: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinitionRequest>>,
}
impl BatchCreateRumMetricDefinitionsInputBuilder {
    /// <p>The name of the CloudWatch RUM app monitor that is to send the metrics.</p>
    /// This field is required.
    pub fn app_monitor_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_monitor_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudWatch RUM app monitor that is to send the metrics.</p>
    pub fn set_app_monitor_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_monitor_name = input;
        self
    }
    /// <p>The name of the CloudWatch RUM app monitor that is to send the metrics.</p>
    pub fn get_app_monitor_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_monitor_name
    }
    /// <p>The destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the Amazon Resource Name (ARN) of the CloudWatchEvidently experiment that will receive the metrics and an IAM role that has permission to write to the experiment.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::MetricDestination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the Amazon Resource Name (ARN) of the CloudWatchEvidently experiment that will receive the metrics and an IAM role that has permission to write to the experiment.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::MetricDestination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The destination to send the metrics to. Valid values are <code>CloudWatch</code> and <code>Evidently</code>. If you specify <code>Evidently</code>, you must also specify the Amazon Resource Name (ARN) of the CloudWatchEvidently experiment that will receive the metrics and an IAM role that has permission to write to the experiment.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::MetricDestination> {
        &self.destination
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, do not use this parameter.</p>
    /// <p>This parameter specifies the ARN of the Evidently experiment that is to receive the metrics. You must have already defined this experiment as a valid destination. For more information, see <a href="https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_PutRumMetricsDestination.html">PutRumMetricsDestination</a>.</p>
    pub fn destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, do not use this parameter.</p>
    /// <p>This parameter specifies the ARN of the Evidently experiment that is to receive the metrics. You must have already defined this experiment as a valid destination. For more information, see <a href="https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_PutRumMetricsDestination.html">PutRumMetricsDestination</a>.</p>
    pub fn set_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_arn = input;
        self
    }
    /// <p>This parameter is required if <code>Destination</code> is <code>Evidently</code>. If <code>Destination</code> is <code>CloudWatch</code>, do not use this parameter.</p>
    /// <p>This parameter specifies the ARN of the Evidently experiment that is to receive the metrics. You must have already defined this experiment as a valid destination. For more information, see <a href="https://docs.aws.amazon.com/cloudwatchrum/latest/APIReference/API_PutRumMetricsDestination.html">PutRumMetricsDestination</a>.</p>
    pub fn get_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_arn
    }
    /// Appends an item to `metric_definitions`.
    ///
    /// To override the contents of this collection use [`set_metric_definitions`](Self::set_metric_definitions).
    ///
    /// <p>An array of structures which define the metrics that you want to send.</p>
    pub fn metric_definitions(mut self, input: crate::types::MetricDefinitionRequest) -> Self {
        let mut v = self.metric_definitions.unwrap_or_default();
        v.push(input);
        self.metric_definitions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures which define the metrics that you want to send.</p>
    pub fn set_metric_definitions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinitionRequest>>) -> Self {
        self.metric_definitions = input;
        self
    }
    /// <p>An array of structures which define the metrics that you want to send.</p>
    pub fn get_metric_definitions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDefinitionRequest>> {
        &self.metric_definitions
    }
    /// Consumes the builder and constructs a [`BatchCreateRumMetricDefinitionsInput`](crate::operation::batch_create_rum_metric_definitions::BatchCreateRumMetricDefinitionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_create_rum_metric_definitions::BatchCreateRumMetricDefinitionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::batch_create_rum_metric_definitions::BatchCreateRumMetricDefinitionsInput {
                app_monitor_name: self.app_monitor_name,
                destination: self.destination,
                destination_arn: self.destination_arn,
                metric_definitions: self.metric_definitions,
            },
        )
    }
}
