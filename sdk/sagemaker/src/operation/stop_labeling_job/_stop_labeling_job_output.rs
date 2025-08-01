// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopLabelingJobOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StopLabelingJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopLabelingJobOutput {
    /// Creates a new builder-style object to manufacture [`StopLabelingJobOutput`](crate::operation::stop_labeling_job::StopLabelingJobOutput).
    pub fn builder() -> crate::operation::stop_labeling_job::builders::StopLabelingJobOutputBuilder {
        crate::operation::stop_labeling_job::builders::StopLabelingJobOutputBuilder::default()
    }
}

/// A builder for [`StopLabelingJobOutput`](crate::operation::stop_labeling_job::StopLabelingJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopLabelingJobOutputBuilder {
    _request_id: Option<String>,
}
impl StopLabelingJobOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopLabelingJobOutput`](crate::operation::stop_labeling_job::StopLabelingJobOutput).
    pub fn build(self) -> crate::operation::stop_labeling_job::StopLabelingJobOutput {
        crate::operation::stop_labeling_job::StopLabelingJobOutput {
            _request_id: self._request_id,
        }
    }
}
