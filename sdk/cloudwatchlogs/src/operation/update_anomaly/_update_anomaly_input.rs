// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAnomalyInput {
    /// <p>If you are suppressing or unsuppressing an anomaly, specify its unique ID here. You can find anomaly IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub anomaly_id: ::std::option::Option<::std::string::String>,
    /// <p>If you are suppressing or unsuppressing an pattern, specify its unique ID here. You can find pattern IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub pattern_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the anomaly detector that this operation is to act on.</p>
    pub anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    /// <p>Use this to specify whether the suppression to be temporary or infinite. If you specify <code>LIMITED</code>, you must also specify a <code>suppressionPeriod</code>. If you specify <code>INFINITE</code>, any value for <code>suppressionPeriod</code> is ignored.</p>
    pub suppression_type: ::std::option::Option<crate::types::SuppressionType>,
    /// <p>If you are temporarily suppressing an anomaly or pattern, use this structure to specify how long the suppression is to last.</p>
    pub suppression_period: ::std::option::Option<crate::types::SuppressionPeriod>,
    /// <p>Set this to <code>true</code> to prevent CloudWatch Logs from displaying this behavior as an anomaly in the future. The behavior is then treated as baseline behavior. However, if similar but more severe occurrences of this behavior occur in the future, those will still be reported as anomalies.</p>
    /// <p>The default is <code>false</code></p>
    pub baseline: ::std::option::Option<bool>,
}
impl UpdateAnomalyInput {
    /// <p>If you are suppressing or unsuppressing an anomaly, specify its unique ID here. You can find anomaly IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn anomaly_id(&self) -> ::std::option::Option<&str> {
        self.anomaly_id.as_deref()
    }
    /// <p>If you are suppressing or unsuppressing an pattern, specify its unique ID here. You can find pattern IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn pattern_id(&self) -> ::std::option::Option<&str> {
        self.pattern_id.as_deref()
    }
    /// <p>The ARN of the anomaly detector that this operation is to act on.</p>
    pub fn anomaly_detector_arn(&self) -> ::std::option::Option<&str> {
        self.anomaly_detector_arn.as_deref()
    }
    /// <p>Use this to specify whether the suppression to be temporary or infinite. If you specify <code>LIMITED</code>, you must also specify a <code>suppressionPeriod</code>. If you specify <code>INFINITE</code>, any value for <code>suppressionPeriod</code> is ignored.</p>
    pub fn suppression_type(&self) -> ::std::option::Option<&crate::types::SuppressionType> {
        self.suppression_type.as_ref()
    }
    /// <p>If you are temporarily suppressing an anomaly or pattern, use this structure to specify how long the suppression is to last.</p>
    pub fn suppression_period(&self) -> ::std::option::Option<&crate::types::SuppressionPeriod> {
        self.suppression_period.as_ref()
    }
    /// <p>Set this to <code>true</code> to prevent CloudWatch Logs from displaying this behavior as an anomaly in the future. The behavior is then treated as baseline behavior. However, if similar but more severe occurrences of this behavior occur in the future, those will still be reported as anomalies.</p>
    /// <p>The default is <code>false</code></p>
    pub fn baseline(&self) -> ::std::option::Option<bool> {
        self.baseline
    }
}
impl UpdateAnomalyInput {
    /// Creates a new builder-style object to manufacture [`UpdateAnomalyInput`](crate::operation::update_anomaly::UpdateAnomalyInput).
    pub fn builder() -> crate::operation::update_anomaly::builders::UpdateAnomalyInputBuilder {
        crate::operation::update_anomaly::builders::UpdateAnomalyInputBuilder::default()
    }
}

/// A builder for [`UpdateAnomalyInput`](crate::operation::update_anomaly::UpdateAnomalyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAnomalyInputBuilder {
    pub(crate) anomaly_id: ::std::option::Option<::std::string::String>,
    pub(crate) pattern_id: ::std::option::Option<::std::string::String>,
    pub(crate) anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    pub(crate) suppression_type: ::std::option::Option<crate::types::SuppressionType>,
    pub(crate) suppression_period: ::std::option::Option<crate::types::SuppressionPeriod>,
    pub(crate) baseline: ::std::option::Option<bool>,
}
impl UpdateAnomalyInputBuilder {
    /// <p>If you are suppressing or unsuppressing an anomaly, specify its unique ID here. You can find anomaly IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn anomaly_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you are suppressing or unsuppressing an anomaly, specify its unique ID here. You can find anomaly IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn set_anomaly_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_id = input;
        self
    }
    /// <p>If you are suppressing or unsuppressing an anomaly, specify its unique ID here. You can find anomaly IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn get_anomaly_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_id
    }
    /// <p>If you are suppressing or unsuppressing an pattern, specify its unique ID here. You can find pattern IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn pattern_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pattern_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you are suppressing or unsuppressing an pattern, specify its unique ID here. You can find pattern IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn set_pattern_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pattern_id = input;
        self
    }
    /// <p>If you are suppressing or unsuppressing an pattern, specify its unique ID here. You can find pattern IDs by using the <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListAnomalies.html">ListAnomalies</a> operation.</p>
    pub fn get_pattern_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pattern_id
    }
    /// <p>The ARN of the anomaly detector that this operation is to act on.</p>
    /// This field is required.
    pub fn anomaly_detector_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_detector_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the anomaly detector that this operation is to act on.</p>
    pub fn set_anomaly_detector_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_detector_arn = input;
        self
    }
    /// <p>The ARN of the anomaly detector that this operation is to act on.</p>
    pub fn get_anomaly_detector_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_detector_arn
    }
    /// <p>Use this to specify whether the suppression to be temporary or infinite. If you specify <code>LIMITED</code>, you must also specify a <code>suppressionPeriod</code>. If you specify <code>INFINITE</code>, any value for <code>suppressionPeriod</code> is ignored.</p>
    pub fn suppression_type(mut self, input: crate::types::SuppressionType) -> Self {
        self.suppression_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this to specify whether the suppression to be temporary or infinite. If you specify <code>LIMITED</code>, you must also specify a <code>suppressionPeriod</code>. If you specify <code>INFINITE</code>, any value for <code>suppressionPeriod</code> is ignored.</p>
    pub fn set_suppression_type(mut self, input: ::std::option::Option<crate::types::SuppressionType>) -> Self {
        self.suppression_type = input;
        self
    }
    /// <p>Use this to specify whether the suppression to be temporary or infinite. If you specify <code>LIMITED</code>, you must also specify a <code>suppressionPeriod</code>. If you specify <code>INFINITE</code>, any value for <code>suppressionPeriod</code> is ignored.</p>
    pub fn get_suppression_type(&self) -> &::std::option::Option<crate::types::SuppressionType> {
        &self.suppression_type
    }
    /// <p>If you are temporarily suppressing an anomaly or pattern, use this structure to specify how long the suppression is to last.</p>
    pub fn suppression_period(mut self, input: crate::types::SuppressionPeriod) -> Self {
        self.suppression_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you are temporarily suppressing an anomaly or pattern, use this structure to specify how long the suppression is to last.</p>
    pub fn set_suppression_period(mut self, input: ::std::option::Option<crate::types::SuppressionPeriod>) -> Self {
        self.suppression_period = input;
        self
    }
    /// <p>If you are temporarily suppressing an anomaly or pattern, use this structure to specify how long the suppression is to last.</p>
    pub fn get_suppression_period(&self) -> &::std::option::Option<crate::types::SuppressionPeriod> {
        &self.suppression_period
    }
    /// <p>Set this to <code>true</code> to prevent CloudWatch Logs from displaying this behavior as an anomaly in the future. The behavior is then treated as baseline behavior. However, if similar but more severe occurrences of this behavior occur in the future, those will still be reported as anomalies.</p>
    /// <p>The default is <code>false</code></p>
    pub fn baseline(mut self, input: bool) -> Self {
        self.baseline = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set this to <code>true</code> to prevent CloudWatch Logs from displaying this behavior as an anomaly in the future. The behavior is then treated as baseline behavior. However, if similar but more severe occurrences of this behavior occur in the future, those will still be reported as anomalies.</p>
    /// <p>The default is <code>false</code></p>
    pub fn set_baseline(mut self, input: ::std::option::Option<bool>) -> Self {
        self.baseline = input;
        self
    }
    /// <p>Set this to <code>true</code> to prevent CloudWatch Logs from displaying this behavior as an anomaly in the future. The behavior is then treated as baseline behavior. However, if similar but more severe occurrences of this behavior occur in the future, those will still be reported as anomalies.</p>
    /// <p>The default is <code>false</code></p>
    pub fn get_baseline(&self) -> &::std::option::Option<bool> {
        &self.baseline
    }
    /// Consumes the builder and constructs a [`UpdateAnomalyInput`](crate::operation::update_anomaly::UpdateAnomalyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_anomaly::UpdateAnomalyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_anomaly::UpdateAnomalyInput {
            anomaly_id: self.anomaly_id,
            pattern_id: self.pattern_id,
            anomaly_detector_arn: self.anomaly_detector_arn,
            suppression_type: self.suppression_type,
            suppression_period: self.suppression_period,
            baseline: self.baseline,
        })
    }
}
