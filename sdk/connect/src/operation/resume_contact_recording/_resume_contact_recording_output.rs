// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResumeContactRecordingOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ResumeContactRecordingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ResumeContactRecordingOutput {
    /// Creates a new builder-style object to manufacture [`ResumeContactRecordingOutput`](crate::operation::resume_contact_recording::ResumeContactRecordingOutput).
    pub fn builder() -> crate::operation::resume_contact_recording::builders::ResumeContactRecordingOutputBuilder {
        crate::operation::resume_contact_recording::builders::ResumeContactRecordingOutputBuilder::default()
    }
}

/// A builder for [`ResumeContactRecordingOutput`](crate::operation::resume_contact_recording::ResumeContactRecordingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResumeContactRecordingOutputBuilder {
    _request_id: Option<String>,
}
impl ResumeContactRecordingOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ResumeContactRecordingOutput`](crate::operation::resume_contact_recording::ResumeContactRecordingOutput).
    pub fn build(self) -> crate::operation::resume_contact_recording::ResumeContactRecordingOutput {
        crate::operation::resume_contact_recording::ResumeContactRecordingOutput {
            _request_id: self._request_id,
        }
    }
}
