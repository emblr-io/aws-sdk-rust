// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides summary information about a monitor alert.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MonitoringAlertSummary {
    /// <p>The name of a monitoring alert.</p>
    pub monitoring_alert_name: ::std::option::Option<::std::string::String>,
    /// <p>A timestamp that indicates when a monitor alert was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp that indicates when a monitor alert was last updated.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current status of an alert.</p>
    pub alert_status: ::std::option::Option<crate::types::MonitoringAlertStatus>,
    /// <p>Within <code>EvaluationPeriod</code>, how many execution failures will raise an alert.</p>
    pub datapoints_to_alert: ::std::option::Option<i32>,
    /// <p>The number of most recent monitoring executions to consider when evaluating alert status.</p>
    pub evaluation_period: ::std::option::Option<i32>,
    /// <p>A list of alert actions taken in response to an alert going into <code>InAlert</code> status.</p>
    pub actions: ::std::option::Option<crate::types::MonitoringAlertActions>,
}
impl MonitoringAlertSummary {
    /// <p>The name of a monitoring alert.</p>
    pub fn monitoring_alert_name(&self) -> ::std::option::Option<&str> {
        self.monitoring_alert_name.as_deref()
    }
    /// <p>A timestamp that indicates when a monitor alert was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>A timestamp that indicates when a monitor alert was last updated.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The current status of an alert.</p>
    pub fn alert_status(&self) -> ::std::option::Option<&crate::types::MonitoringAlertStatus> {
        self.alert_status.as_ref()
    }
    /// <p>Within <code>EvaluationPeriod</code>, how many execution failures will raise an alert.</p>
    pub fn datapoints_to_alert(&self) -> ::std::option::Option<i32> {
        self.datapoints_to_alert
    }
    /// <p>The number of most recent monitoring executions to consider when evaluating alert status.</p>
    pub fn evaluation_period(&self) -> ::std::option::Option<i32> {
        self.evaluation_period
    }
    /// <p>A list of alert actions taken in response to an alert going into <code>InAlert</code> status.</p>
    pub fn actions(&self) -> ::std::option::Option<&crate::types::MonitoringAlertActions> {
        self.actions.as_ref()
    }
}
impl MonitoringAlertSummary {
    /// Creates a new builder-style object to manufacture [`MonitoringAlertSummary`](crate::types::MonitoringAlertSummary).
    pub fn builder() -> crate::types::builders::MonitoringAlertSummaryBuilder {
        crate::types::builders::MonitoringAlertSummaryBuilder::default()
    }
}

/// A builder for [`MonitoringAlertSummary`](crate::types::MonitoringAlertSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MonitoringAlertSummaryBuilder {
    pub(crate) monitoring_alert_name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) alert_status: ::std::option::Option<crate::types::MonitoringAlertStatus>,
    pub(crate) datapoints_to_alert: ::std::option::Option<i32>,
    pub(crate) evaluation_period: ::std::option::Option<i32>,
    pub(crate) actions: ::std::option::Option<crate::types::MonitoringAlertActions>,
}
impl MonitoringAlertSummaryBuilder {
    /// <p>The name of a monitoring alert.</p>
    /// This field is required.
    pub fn monitoring_alert_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitoring_alert_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a monitoring alert.</p>
    pub fn set_monitoring_alert_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitoring_alert_name = input;
        self
    }
    /// <p>The name of a monitoring alert.</p>
    pub fn get_monitoring_alert_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitoring_alert_name
    }
    /// <p>A timestamp that indicates when a monitor alert was created.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when a monitor alert was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>A timestamp that indicates when a monitor alert was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>A timestamp that indicates when a monitor alert was last updated.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when a monitor alert was last updated.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>A timestamp that indicates when a monitor alert was last updated.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The current status of an alert.</p>
    /// This field is required.
    pub fn alert_status(mut self, input: crate::types::MonitoringAlertStatus) -> Self {
        self.alert_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of an alert.</p>
    pub fn set_alert_status(mut self, input: ::std::option::Option<crate::types::MonitoringAlertStatus>) -> Self {
        self.alert_status = input;
        self
    }
    /// <p>The current status of an alert.</p>
    pub fn get_alert_status(&self) -> &::std::option::Option<crate::types::MonitoringAlertStatus> {
        &self.alert_status
    }
    /// <p>Within <code>EvaluationPeriod</code>, how many execution failures will raise an alert.</p>
    /// This field is required.
    pub fn datapoints_to_alert(mut self, input: i32) -> Self {
        self.datapoints_to_alert = ::std::option::Option::Some(input);
        self
    }
    /// <p>Within <code>EvaluationPeriod</code>, how many execution failures will raise an alert.</p>
    pub fn set_datapoints_to_alert(mut self, input: ::std::option::Option<i32>) -> Self {
        self.datapoints_to_alert = input;
        self
    }
    /// <p>Within <code>EvaluationPeriod</code>, how many execution failures will raise an alert.</p>
    pub fn get_datapoints_to_alert(&self) -> &::std::option::Option<i32> {
        &self.datapoints_to_alert
    }
    /// <p>The number of most recent monitoring executions to consider when evaluating alert status.</p>
    /// This field is required.
    pub fn evaluation_period(mut self, input: i32) -> Self {
        self.evaluation_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of most recent monitoring executions to consider when evaluating alert status.</p>
    pub fn set_evaluation_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.evaluation_period = input;
        self
    }
    /// <p>The number of most recent monitoring executions to consider when evaluating alert status.</p>
    pub fn get_evaluation_period(&self) -> &::std::option::Option<i32> {
        &self.evaluation_period
    }
    /// <p>A list of alert actions taken in response to an alert going into <code>InAlert</code> status.</p>
    /// This field is required.
    pub fn actions(mut self, input: crate::types::MonitoringAlertActions) -> Self {
        self.actions = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of alert actions taken in response to an alert going into <code>InAlert</code> status.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<crate::types::MonitoringAlertActions>) -> Self {
        self.actions = input;
        self
    }
    /// <p>A list of alert actions taken in response to an alert going into <code>InAlert</code> status.</p>
    pub fn get_actions(&self) -> &::std::option::Option<crate::types::MonitoringAlertActions> {
        &self.actions
    }
    /// Consumes the builder and constructs a [`MonitoringAlertSummary`](crate::types::MonitoringAlertSummary).
    pub fn build(self) -> crate::types::MonitoringAlertSummary {
        crate::types::MonitoringAlertSummary {
            monitoring_alert_name: self.monitoring_alert_name,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            alert_status: self.alert_status,
            datapoints_to_alert: self.datapoints_to_alert,
            evaluation_period: self.evaluation_period,
            actions: self.actions,
        }
    }
}
