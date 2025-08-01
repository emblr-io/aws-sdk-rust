// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::create_practice_run_configuration::_create_practice_run_configuration_output::CreatePracticeRunConfigurationOutputBuilder;

pub use crate::operation::create_practice_run_configuration::_create_practice_run_configuration_input::CreatePracticeRunConfigurationInputBuilder;

impl crate::operation::create_practice_run_configuration::builders::CreatePracticeRunConfigurationInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.create_practice_run_configuration();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `CreatePracticeRunConfiguration`.
///
/// <p>A practice run configuration for zonal autoshift is required when you enable zonal autoshift. A practice run configuration includes specifications for blocked dates and blocked time windows, and for Amazon CloudWatch alarms that you create to use with practice runs. The alarms that you specify are an <i>outcome alarm</i>, to monitor application health during practice runs and, optionally, a <i>blocking alarm</i>, to block practice runs from starting.</p>
/// <p>When a resource has a practice run configuration, ARC starts zonal shifts for the resource weekly, to shift traffic for practice runs. Practice runs help you to ensure that shifting away traffic from an Availability Zone during an autoshift is safe for your application.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-autoshift.considerations.html"> Considerations when you configure zonal autoshift</a> in the Amazon Application Recovery Controller Developer Guide.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct CreatePracticeRunConfigurationFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::create_practice_run_configuration::builders::CreatePracticeRunConfigurationInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationOutput,
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationError,
    > for CreatePracticeRunConfigurationFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationOutput,
            crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl CreatePracticeRunConfigurationFluentBuilder {
    /// Creates a new `CreatePracticeRunConfigurationFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the CreatePracticeRunConfiguration as a reference.
    pub fn as_input(&self) -> &crate::operation::create_practice_run_configuration::builders::CreatePracticeRunConfigurationInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::create_practice_run_configuration::CreatePracticeRunConfiguration::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfiguration::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationOutput,
        crate::operation::create_practice_run_configuration::CreatePracticeRunConfigurationError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The identifier of the resource that Amazon Web Services shifts traffic for with a practice run zonal shift. The identifier is the Amazon Resource Name (ARN) for the resource.</p>
    /// <p>Amazon Application Recovery Controller currently supports enabling the following resources for zonal shift and zonal autoshift:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.ec2-auto-scaling-groups.html">Amazon EC2 Auto Scaling groups</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.eks.html">Amazon Elastic Kubernetes Service</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.app-load-balancers.html">Application Load Balancer</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.network-load-balancers.html">Network Load Balancer</a></p></li>
    /// </ul>
    pub fn resource_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.resource_identifier(input.into());
        self
    }
    /// <p>The identifier of the resource that Amazon Web Services shifts traffic for with a practice run zonal shift. The identifier is the Amazon Resource Name (ARN) for the resource.</p>
    /// <p>Amazon Application Recovery Controller currently supports enabling the following resources for zonal shift and zonal autoshift:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.ec2-auto-scaling-groups.html">Amazon EC2 Auto Scaling groups</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.eks.html">Amazon Elastic Kubernetes Service</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.app-load-balancers.html">Application Load Balancer</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.network-load-balancers.html">Network Load Balancer</a></p></li>
    /// </ul>
    pub fn set_resource_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_resource_identifier(input);
        self
    }
    /// <p>The identifier of the resource that Amazon Web Services shifts traffic for with a practice run zonal shift. The identifier is the Amazon Resource Name (ARN) for the resource.</p>
    /// <p>Amazon Application Recovery Controller currently supports enabling the following resources for zonal shift and zonal autoshift:</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.ec2-auto-scaling-groups.html">Amazon EC2 Auto Scaling groups</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.eks.html">Amazon Elastic Kubernetes Service</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.app-load-balancers.html">Application Load Balancer</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.network-load-balancers.html">Network Load Balancer</a></p></li>
    /// </ul>
    pub fn get_resource_identifier(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_resource_identifier()
    }
    ///
    /// Appends an item to `blockedWindows`.
    ///
    /// To override the contents of this collection use [`set_blocked_windows`](Self::set_blocked_windows).
    ///
    /// <p>Optionally, you can block ARC from starting practice runs for specific windows of days and times.</p>
    /// <p>The format for blocked windows is: DAY:HH:SS-DAY:HH:SS. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Also, be aware of potential time adjustments that might be required for daylight saving time differences. Separate multiple blocked windows with spaces.</p>
    /// <p>For example, say you run business report summaries three days a week. For this scenario, you might set the following recurring days and times as blocked windows, for example: <code>MON-20:30-21:30 WED-20:30-21:30 FRI-20:30-21:30</code>.</p>
    pub fn blocked_windows(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.blocked_windows(input.into());
        self
    }
    /// <p>Optionally, you can block ARC from starting practice runs for specific windows of days and times.</p>
    /// <p>The format for blocked windows is: DAY:HH:SS-DAY:HH:SS. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Also, be aware of potential time adjustments that might be required for daylight saving time differences. Separate multiple blocked windows with spaces.</p>
    /// <p>For example, say you run business report summaries three days a week. For this scenario, you might set the following recurring days and times as blocked windows, for example: <code>MON-20:30-21:30 WED-20:30-21:30 FRI-20:30-21:30</code>.</p>
    pub fn set_blocked_windows(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_blocked_windows(input);
        self
    }
    /// <p>Optionally, you can block ARC from starting practice runs for specific windows of days and times.</p>
    /// <p>The format for blocked windows is: DAY:HH:SS-DAY:HH:SS. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Also, be aware of potential time adjustments that might be required for daylight saving time differences. Separate multiple blocked windows with spaces.</p>
    /// <p>For example, say you run business report summaries three days a week. For this scenario, you might set the following recurring days and times as blocked windows, for example: <code>MON-20:30-21:30 WED-20:30-21:30 FRI-20:30-21:30</code>.</p>
    pub fn get_blocked_windows(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_blocked_windows()
    }
    ///
    /// Appends an item to `blockedDates`.
    ///
    /// To override the contents of this collection use [`set_blocked_dates`](Self::set_blocked_dates).
    ///
    /// <p>Optionally, you can block ARC from starting practice runs for a resource on specific calendar dates.</p>
    /// <p>The format for blocked dates is: YYYY-MM-DD. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Separate multiple blocked dates with spaces.</p>
    /// <p>For example, if you have an application update scheduled to launch on May 1, 2024, and you don't want practice runs to shift traffic away at that time, you could set a blocked date for <code>2024-05-01</code>.</p>
    pub fn blocked_dates(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.blocked_dates(input.into());
        self
    }
    /// <p>Optionally, you can block ARC from starting practice runs for a resource on specific calendar dates.</p>
    /// <p>The format for blocked dates is: YYYY-MM-DD. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Separate multiple blocked dates with spaces.</p>
    /// <p>For example, if you have an application update scheduled to launch on May 1, 2024, and you don't want practice runs to shift traffic away at that time, you could set a blocked date for <code>2024-05-01</code>.</p>
    pub fn set_blocked_dates(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_blocked_dates(input);
        self
    }
    /// <p>Optionally, you can block ARC from starting practice runs for a resource on specific calendar dates.</p>
    /// <p>The format for blocked dates is: YYYY-MM-DD. Keep in mind, when you specify dates, that dates and times for practice runs are in UTC. Separate multiple blocked dates with spaces.</p>
    /// <p>For example, if you have an application update scheduled to launch on May 1, 2024, and you don't want practice runs to shift traffic away at that time, you could set a blocked date for <code>2024-05-01</code>.</p>
    pub fn get_blocked_dates(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_blocked_dates()
    }
    ///
    /// Appends an item to `blockingAlarms`.
    ///
    /// To override the contents of this collection use [`set_blocking_alarms`](Self::set_blocking_alarms).
    ///
    /// <p>An Amazon CloudWatch alarm that you can specify for zonal autoshift practice runs. This alarm blocks ARC from starting practice run zonal shifts, and ends a practice run that's in progress, when the alarm is in an <code>ALARM</code> state.</p>
    pub fn blocking_alarms(mut self, input: crate::types::ControlCondition) -> Self {
        self.inner = self.inner.blocking_alarms(input);
        self
    }
    /// <p>An Amazon CloudWatch alarm that you can specify for zonal autoshift practice runs. This alarm blocks ARC from starting practice run zonal shifts, and ends a practice run that's in progress, when the alarm is in an <code>ALARM</code> state.</p>
    pub fn set_blocking_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>) -> Self {
        self.inner = self.inner.set_blocking_alarms(input);
        self
    }
    /// <p>An Amazon CloudWatch alarm that you can specify for zonal autoshift practice runs. This alarm blocks ARC from starting practice run zonal shifts, and ends a practice run that's in progress, when the alarm is in an <code>ALARM</code> state.</p>
    pub fn get_blocking_alarms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>> {
        self.inner.get_blocking_alarms()
    }
    ///
    /// Appends an item to `outcomeAlarms`.
    ///
    /// To override the contents of this collection use [`set_outcome_alarms`](Self::set_outcome_alarms).
    ///
    /// <p>The <i>outcome alarm</i> for practice runs is a required Amazon CloudWatch alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    /// <p>Configure the alarm to monitor the health of your application when traffic is shifted away from an Availability Zone during each practice run. You should configure the alarm to go into an <code>ALARM</code> state if your application is impacted by the zonal shift, and you want to stop the zonal shift, to let traffic for the resource return to the Availability Zone.</p>
    pub fn outcome_alarms(mut self, input: crate::types::ControlCondition) -> Self {
        self.inner = self.inner.outcome_alarms(input);
        self
    }
    /// <p>The <i>outcome alarm</i> for practice runs is a required Amazon CloudWatch alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    /// <p>Configure the alarm to monitor the health of your application when traffic is shifted away from an Availability Zone during each practice run. You should configure the alarm to go into an <code>ALARM</code> state if your application is impacted by the zonal shift, and you want to stop the zonal shift, to let traffic for the resource return to the Availability Zone.</p>
    pub fn set_outcome_alarms(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>>) -> Self {
        self.inner = self.inner.set_outcome_alarms(input);
        self
    }
    /// <p>The <i>outcome alarm</i> for practice runs is a required Amazon CloudWatch alarm that you specify that ends a practice run when the alarm is in an <code>ALARM</code> state.</p>
    /// <p>Configure the alarm to monitor the health of your application when traffic is shifted away from an Availability Zone during each practice run. You should configure the alarm to go into an <code>ALARM</code> state if your application is impacted by the zonal shift, and you want to stop the zonal shift, to let traffic for the resource return to the Availability Zone.</p>
    pub fn get_outcome_alarms(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ControlCondition>> {
        self.inner.get_outcome_alarms()
    }
}
