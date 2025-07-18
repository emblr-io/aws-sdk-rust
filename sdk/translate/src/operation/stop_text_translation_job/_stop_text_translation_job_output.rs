// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopTextTranslationJobOutput {
    /// <p>The job ID of the stopped batch translation job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the designated job. Upon successful completion, the job's status will be <code>STOPPED</code>.</p>
    pub job_status: ::std::option::Option<crate::types::JobStatus>,
    _request_id: Option<String>,
}
impl StopTextTranslationJobOutput {
    /// <p>The job ID of the stopped batch translation job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The status of the designated job. Upon successful completion, the job's status will be <code>STOPPED</code>.</p>
    pub fn job_status(&self) -> ::std::option::Option<&crate::types::JobStatus> {
        self.job_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopTextTranslationJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopTextTranslationJobOutput {
    /// Creates a new builder-style object to manufacture [`StopTextTranslationJobOutput`](crate::operation::stop_text_translation_job::StopTextTranslationJobOutput).
    pub fn builder() -> crate::operation::stop_text_translation_job::builders::StopTextTranslationJobOutputBuilder {
        crate::operation::stop_text_translation_job::builders::StopTextTranslationJobOutputBuilder::default()
    }
}

/// A builder for [`StopTextTranslationJobOutput`](crate::operation::stop_text_translation_job::StopTextTranslationJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopTextTranslationJobOutputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_status: ::std::option::Option<crate::types::JobStatus>,
    _request_id: Option<String>,
}
impl StopTextTranslationJobOutputBuilder {
    /// <p>The job ID of the stopped batch translation job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job ID of the stopped batch translation job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The job ID of the stopped batch translation job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The status of the designated job. Upon successful completion, the job's status will be <code>STOPPED</code>.</p>
    pub fn job_status(mut self, input: crate::types::JobStatus) -> Self {
        self.job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the designated job. Upon successful completion, the job's status will be <code>STOPPED</code>.</p>
    pub fn set_job_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.job_status = input;
        self
    }
    /// <p>The status of the designated job. Upon successful completion, the job's status will be <code>STOPPED</code>.</p>
    pub fn get_job_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.job_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopTextTranslationJobOutput`](crate::operation::stop_text_translation_job::StopTextTranslationJobOutput).
    pub fn build(self) -> crate::operation::stop_text_translation_job::StopTextTranslationJobOutput {
        crate::operation::stop_text_translation_job::StopTextTranslationJobOutput {
            job_id: self.job_id,
            job_status: self.job_status,
            _request_id: self._request_id,
        }
    }
}
