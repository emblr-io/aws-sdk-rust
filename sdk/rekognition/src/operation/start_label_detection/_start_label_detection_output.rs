// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartLabelDetectionOutput {
    /// <p>The identifier for the label detection job. Use <code>JobId</code> to identify the job in a subsequent call to <code>GetLabelDetection</code>.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartLabelDetectionOutput {
    /// <p>The identifier for the label detection job. Use <code>JobId</code> to identify the job in a subsequent call to <code>GetLabelDetection</code>.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartLabelDetectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartLabelDetectionOutput {
    /// Creates a new builder-style object to manufacture [`StartLabelDetectionOutput`](crate::operation::start_label_detection::StartLabelDetectionOutput).
    pub fn builder() -> crate::operation::start_label_detection::builders::StartLabelDetectionOutputBuilder {
        crate::operation::start_label_detection::builders::StartLabelDetectionOutputBuilder::default()
    }
}

/// A builder for [`StartLabelDetectionOutput`](crate::operation::start_label_detection::StartLabelDetectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartLabelDetectionOutputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartLabelDetectionOutputBuilder {
    /// <p>The identifier for the label detection job. Use <code>JobId</code> to identify the job in a subsequent call to <code>GetLabelDetection</code>.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the label detection job. Use <code>JobId</code> to identify the job in a subsequent call to <code>GetLabelDetection</code>.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier for the label detection job. Use <code>JobId</code> to identify the job in a subsequent call to <code>GetLabelDetection</code>.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartLabelDetectionOutput`](crate::operation::start_label_detection::StartLabelDetectionOutput).
    pub fn build(self) -> crate::operation::start_label_detection::StartLabelDetectionOutput {
        crate::operation::start_label_detection::StartLabelDetectionOutput {
            job_id: self.job_id,
            _request_id: self._request_id,
        }
    }
}
