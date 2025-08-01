// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAnomalyDetectorOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteAnomalyDetectorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteAnomalyDetectorOutput {
    /// Creates a new builder-style object to manufacture [`DeleteAnomalyDetectorOutput`](crate::operation::delete_anomaly_detector::DeleteAnomalyDetectorOutput).
    pub fn builder() -> crate::operation::delete_anomaly_detector::builders::DeleteAnomalyDetectorOutputBuilder {
        crate::operation::delete_anomaly_detector::builders::DeleteAnomalyDetectorOutputBuilder::default()
    }
}

/// A builder for [`DeleteAnomalyDetectorOutput`](crate::operation::delete_anomaly_detector::DeleteAnomalyDetectorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAnomalyDetectorOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteAnomalyDetectorOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteAnomalyDetectorOutput`](crate::operation::delete_anomaly_detector::DeleteAnomalyDetectorOutput).
    pub fn build(self) -> crate::operation::delete_anomaly_detector::DeleteAnomalyDetectorOutput {
        crate::operation::delete_anomaly_detector::DeleteAnomalyDetectorOutput {
            _request_id: self._request_id,
        }
    }
}
