// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAnomalyDetectorOutput {
    /// <p>The ARN of the updated detector.</p>
    pub anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateAnomalyDetectorOutput {
    /// <p>The ARN of the updated detector.</p>
    pub fn anomaly_detector_arn(&self) -> ::std::option::Option<&str> {
        self.anomaly_detector_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateAnomalyDetectorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateAnomalyDetectorOutput {
    /// Creates a new builder-style object to manufacture [`UpdateAnomalyDetectorOutput`](crate::operation::update_anomaly_detector::UpdateAnomalyDetectorOutput).
    pub fn builder() -> crate::operation::update_anomaly_detector::builders::UpdateAnomalyDetectorOutputBuilder {
        crate::operation::update_anomaly_detector::builders::UpdateAnomalyDetectorOutputBuilder::default()
    }
}

/// A builder for [`UpdateAnomalyDetectorOutput`](crate::operation::update_anomaly_detector::UpdateAnomalyDetectorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAnomalyDetectorOutputBuilder {
    pub(crate) anomaly_detector_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateAnomalyDetectorOutputBuilder {
    /// <p>The ARN of the updated detector.</p>
    pub fn anomaly_detector_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_detector_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the updated detector.</p>
    pub fn set_anomaly_detector_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_detector_arn = input;
        self
    }
    /// <p>The ARN of the updated detector.</p>
    pub fn get_anomaly_detector_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_detector_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateAnomalyDetectorOutput`](crate::operation::update_anomaly_detector::UpdateAnomalyDetectorOutput).
    pub fn build(self) -> crate::operation::update_anomaly_detector::UpdateAnomalyDetectorOutput {
        crate::operation::update_anomaly_detector::UpdateAnomalyDetectorOutput {
            anomaly_detector_arn: self.anomaly_detector_arn,
            _request_id: self._request_id,
        }
    }
}
