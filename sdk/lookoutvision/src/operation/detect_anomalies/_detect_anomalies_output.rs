// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectAnomaliesOutput {
    /// <p>The results of the <code>DetectAnomalies</code> operation.</p>
    pub detect_anomaly_result: ::std::option::Option<crate::types::DetectAnomalyResult>,
    _request_id: Option<String>,
}
impl DetectAnomaliesOutput {
    /// <p>The results of the <code>DetectAnomalies</code> operation.</p>
    pub fn detect_anomaly_result(&self) -> ::std::option::Option<&crate::types::DetectAnomalyResult> {
        self.detect_anomaly_result.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DetectAnomaliesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DetectAnomaliesOutput {
    /// Creates a new builder-style object to manufacture [`DetectAnomaliesOutput`](crate::operation::detect_anomalies::DetectAnomaliesOutput).
    pub fn builder() -> crate::operation::detect_anomalies::builders::DetectAnomaliesOutputBuilder {
        crate::operation::detect_anomalies::builders::DetectAnomaliesOutputBuilder::default()
    }
}

/// A builder for [`DetectAnomaliesOutput`](crate::operation::detect_anomalies::DetectAnomaliesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectAnomaliesOutputBuilder {
    pub(crate) detect_anomaly_result: ::std::option::Option<crate::types::DetectAnomalyResult>,
    _request_id: Option<String>,
}
impl DetectAnomaliesOutputBuilder {
    /// <p>The results of the <code>DetectAnomalies</code> operation.</p>
    pub fn detect_anomaly_result(mut self, input: crate::types::DetectAnomalyResult) -> Self {
        self.detect_anomaly_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The results of the <code>DetectAnomalies</code> operation.</p>
    pub fn set_detect_anomaly_result(mut self, input: ::std::option::Option<crate::types::DetectAnomalyResult>) -> Self {
        self.detect_anomaly_result = input;
        self
    }
    /// <p>The results of the <code>DetectAnomalies</code> operation.</p>
    pub fn get_detect_anomaly_result(&self) -> &::std::option::Option<crate::types::DetectAnomalyResult> {
        &self.detect_anomaly_result
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DetectAnomaliesOutput`](crate::operation::detect_anomalies::DetectAnomaliesOutput).
    pub fn build(self) -> crate::operation::detect_anomalies::DetectAnomaliesOutput {
        crate::operation::detect_anomalies::DetectAnomaliesOutput {
            detect_anomaly_result: self.detect_anomaly_result,
            _request_id: self._request_id,
        }
    }
}
