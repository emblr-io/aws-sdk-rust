// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTranscriptionJobOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteTranscriptionJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteTranscriptionJobOutput {
    /// Creates a new builder-style object to manufacture [`DeleteTranscriptionJobOutput`](crate::operation::delete_transcription_job::DeleteTranscriptionJobOutput).
    pub fn builder() -> crate::operation::delete_transcription_job::builders::DeleteTranscriptionJobOutputBuilder {
        crate::operation::delete_transcription_job::builders::DeleteTranscriptionJobOutputBuilder::default()
    }
}

/// A builder for [`DeleteTranscriptionJobOutput`](crate::operation::delete_transcription_job::DeleteTranscriptionJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTranscriptionJobOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteTranscriptionJobOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteTranscriptionJobOutput`](crate::operation::delete_transcription_job::DeleteTranscriptionJobOutput).
    pub fn build(self) -> crate::operation::delete_transcription_job::DeleteTranscriptionJobOutput {
        crate::operation::delete_transcription_job::DeleteTranscriptionJobOutput {
            _request_id: self._request_id,
        }
    }
}
