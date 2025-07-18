// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListModelImportJobsOutput {
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Import job summaries.</p>
    pub model_import_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelImportJobSummary>>,
    _request_id: Option<String>,
}
impl ListModelImportJobsOutput {
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Import job summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.model_import_job_summaries.is_none()`.
    pub fn model_import_job_summaries(&self) -> &[crate::types::ModelImportJobSummary] {
        self.model_import_job_summaries.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListModelImportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListModelImportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListModelImportJobsOutput`](crate::operation::list_model_import_jobs::ListModelImportJobsOutput).
    pub fn builder() -> crate::operation::list_model_import_jobs::builders::ListModelImportJobsOutputBuilder {
        crate::operation::list_model_import_jobs::builders::ListModelImportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListModelImportJobsOutput`](crate::operation::list_model_import_jobs::ListModelImportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListModelImportJobsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) model_import_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ModelImportJobSummary>>,
    _request_id: Option<String>,
}
impl ListModelImportJobsOutputBuilder {
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `model_import_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_model_import_job_summaries`](Self::set_model_import_job_summaries).
    ///
    /// <p>Import job summaries.</p>
    pub fn model_import_job_summaries(mut self, input: crate::types::ModelImportJobSummary) -> Self {
        let mut v = self.model_import_job_summaries.unwrap_or_default();
        v.push(input);
        self.model_import_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>Import job summaries.</p>
    pub fn set_model_import_job_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ModelImportJobSummary>>) -> Self {
        self.model_import_job_summaries = input;
        self
    }
    /// <p>Import job summaries.</p>
    pub fn get_model_import_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ModelImportJobSummary>> {
        &self.model_import_job_summaries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListModelImportJobsOutput`](crate::operation::list_model_import_jobs::ListModelImportJobsOutput).
    pub fn build(self) -> crate::operation::list_model_import_jobs::ListModelImportJobsOutput {
        crate::operation::list_model_import_jobs::ListModelImportJobsOutput {
            next_token: self.next_token,
            model_import_job_summaries: self.model_import_job_summaries,
            _request_id: self._request_id,
        }
    }
}
