// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListModelCardExportJobsOutput {
    /// <p>The summaries of the listed model card export jobs.</p>
    pub model_card_export_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardExportJobSummary>>,
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model card export jobs, use it in the subsequent request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListModelCardExportJobsOutput {
    /// <p>The summaries of the listed model card export jobs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.model_card_export_job_summaries.is_none()`.
    pub fn model_card_export_job_summaries(&self) -> &[crate::types::ModelCardExportJobSummary] {
        self.model_card_export_job_summaries.as_deref().unwrap_or_default()
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model card export jobs, use it in the subsequent request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListModelCardExportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListModelCardExportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListModelCardExportJobsOutput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsOutput).
    pub fn builder() -> crate::operation::list_model_card_export_jobs::builders::ListModelCardExportJobsOutputBuilder {
        crate::operation::list_model_card_export_jobs::builders::ListModelCardExportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListModelCardExportJobsOutput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListModelCardExportJobsOutputBuilder {
    pub(crate) model_card_export_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardExportJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListModelCardExportJobsOutputBuilder {
    /// Appends an item to `model_card_export_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_model_card_export_job_summaries`](Self::set_model_card_export_job_summaries).
    ///
    /// <p>The summaries of the listed model card export jobs.</p>
    pub fn model_card_export_job_summaries(mut self, input: crate::types::ModelCardExportJobSummary) -> Self {
        let mut v = self.model_card_export_job_summaries.unwrap_or_default();
        v.push(input);
        self.model_card_export_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The summaries of the listed model card export jobs.</p>
    pub fn set_model_card_export_job_summaries(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ModelCardExportJobSummary>>,
    ) -> Self {
        self.model_card_export_job_summaries = input;
        self
    }
    /// <p>The summaries of the listed model card export jobs.</p>
    pub fn get_model_card_export_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ModelCardExportJobSummary>> {
        &self.model_card_export_job_summaries
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model card export jobs, use it in the subsequent request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model card export jobs, use it in the subsequent request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, SageMaker returns this token. To retrieve the next set of model card export jobs, use it in the subsequent request.</p>
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
    /// Consumes the builder and constructs a [`ListModelCardExportJobsOutput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsOutput).
    pub fn build(self) -> crate::operation::list_model_card_export_jobs::ListModelCardExportJobsOutput {
        crate::operation::list_model_card_export_jobs::ListModelCardExportJobsOutput {
            model_card_export_job_summaries: self.model_card_export_job_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
