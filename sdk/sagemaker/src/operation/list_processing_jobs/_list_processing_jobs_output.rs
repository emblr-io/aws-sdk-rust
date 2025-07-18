// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProcessingJobsOutput {
    /// <p>An array of <code>ProcessingJobSummary</code> objects, each listing a processing job.</p>
    pub processing_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ProcessingJobSummary>>,
    /// <p>If the response is truncated, Amazon SageMaker returns this token. To retrieve the next set of processing jobs, use it in the subsequent request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProcessingJobsOutput {
    /// <p>An array of <code>ProcessingJobSummary</code> objects, each listing a processing job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.processing_job_summaries.is_none()`.
    pub fn processing_job_summaries(&self) -> &[crate::types::ProcessingJobSummary] {
        self.processing_job_summaries.as_deref().unwrap_or_default()
    }
    /// <p>If the response is truncated, Amazon SageMaker returns this token. To retrieve the next set of processing jobs, use it in the subsequent request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListProcessingJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListProcessingJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListProcessingJobsOutput`](crate::operation::list_processing_jobs::ListProcessingJobsOutput).
    pub fn builder() -> crate::operation::list_processing_jobs::builders::ListProcessingJobsOutputBuilder {
        crate::operation::list_processing_jobs::builders::ListProcessingJobsOutputBuilder::default()
    }
}

/// A builder for [`ListProcessingJobsOutput`](crate::operation::list_processing_jobs::ListProcessingJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProcessingJobsOutputBuilder {
    pub(crate) processing_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ProcessingJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProcessingJobsOutputBuilder {
    /// Appends an item to `processing_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_processing_job_summaries`](Self::set_processing_job_summaries).
    ///
    /// <p>An array of <code>ProcessingJobSummary</code> objects, each listing a processing job.</p>
    pub fn processing_job_summaries(mut self, input: crate::types::ProcessingJobSummary) -> Self {
        let mut v = self.processing_job_summaries.unwrap_or_default();
        v.push(input);
        self.processing_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>ProcessingJobSummary</code> objects, each listing a processing job.</p>
    pub fn set_processing_job_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProcessingJobSummary>>) -> Self {
        self.processing_job_summaries = input;
        self
    }
    /// <p>An array of <code>ProcessingJobSummary</code> objects, each listing a processing job.</p>
    pub fn get_processing_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProcessingJobSummary>> {
        &self.processing_job_summaries
    }
    /// <p>If the response is truncated, Amazon SageMaker returns this token. To retrieve the next set of processing jobs, use it in the subsequent request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon SageMaker returns this token. To retrieve the next set of processing jobs, use it in the subsequent request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon SageMaker returns this token. To retrieve the next set of processing jobs, use it in the subsequent request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListProcessingJobsOutput`](crate::operation::list_processing_jobs::ListProcessingJobsOutput).
    pub fn build(self) -> crate::operation::list_processing_jobs::ListProcessingJobsOutput {
        crate::operation::list_processing_jobs::ListProcessingJobsOutput {
            processing_job_summaries: self.processing_job_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
