// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutFeedbackInput {
    /// <p>The Amazon Resource Name (ARN) of the anomaly detector.</p>
    pub anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    /// <p>Feedback for an anomalous metric.</p>
    pub anomaly_group_time_series_feedback: ::std::option::Option<crate::types::AnomalyGroupTimeSeriesFeedback>,
}
impl PutFeedbackInput {
    /// <p>The Amazon Resource Name (ARN) of the anomaly detector.</p>
    pub fn anomaly_detector_arn(&self) -> ::std::option::Option<&str> {
        self.anomaly_detector_arn.as_deref()
    }
    /// <p>Feedback for an anomalous metric.</p>
    pub fn anomaly_group_time_series_feedback(&self) -> ::std::option::Option<&crate::types::AnomalyGroupTimeSeriesFeedback> {
        self.anomaly_group_time_series_feedback.as_ref()
    }
}
impl PutFeedbackInput {
    /// Creates a new builder-style object to manufacture [`PutFeedbackInput`](crate::operation::put_feedback::PutFeedbackInput).
    pub fn builder() -> crate::operation::put_feedback::builders::PutFeedbackInputBuilder {
        crate::operation::put_feedback::builders::PutFeedbackInputBuilder::default()
    }
}

/// A builder for [`PutFeedbackInput`](crate::operation::put_feedback::PutFeedbackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutFeedbackInputBuilder {
    pub(crate) anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    pub(crate) anomaly_group_time_series_feedback: ::std::option::Option<crate::types::AnomalyGroupTimeSeriesFeedback>,
}
impl PutFeedbackInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the anomaly detector.</p>
    /// This field is required.
    pub fn anomaly_detector_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_detector_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the anomaly detector.</p>
    pub fn set_anomaly_detector_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_detector_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the anomaly detector.</p>
    pub fn get_anomaly_detector_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_detector_arn
    }
    /// <p>Feedback for an anomalous metric.</p>
    /// This field is required.
    pub fn anomaly_group_time_series_feedback(mut self, input: crate::types::AnomalyGroupTimeSeriesFeedback) -> Self {
        self.anomaly_group_time_series_feedback = ::std::option::Option::Some(input);
        self
    }
    /// <p>Feedback for an anomalous metric.</p>
    pub fn set_anomaly_group_time_series_feedback(mut self, input: ::std::option::Option<crate::types::AnomalyGroupTimeSeriesFeedback>) -> Self {
        self.anomaly_group_time_series_feedback = input;
        self
    }
    /// <p>Feedback for an anomalous metric.</p>
    pub fn get_anomaly_group_time_series_feedback(&self) -> &::std::option::Option<crate::types::AnomalyGroupTimeSeriesFeedback> {
        &self.anomaly_group_time_series_feedback
    }
    /// Consumes the builder and constructs a [`PutFeedbackInput`](crate::operation::put_feedback::PutFeedbackInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_feedback::PutFeedbackInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_feedback::PutFeedbackInput {
            anomaly_detector_arn: self.anomaly_detector_arn,
            anomaly_group_time_series_feedback: self.anomaly_group_time_series_feedback,
        })
    }
}
