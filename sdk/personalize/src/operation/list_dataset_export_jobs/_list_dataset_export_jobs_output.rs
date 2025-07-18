// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDatasetExportJobsOutput {
    /// <p>The list of dataset export jobs.</p>
    pub dataset_export_jobs: ::std::option::Option<::std::vec::Vec<crate::types::DatasetExportJobSummary>>,
    /// <p>A token for getting the next set of dataset export jobs (if they exist).</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDatasetExportJobsOutput {
    /// <p>The list of dataset export jobs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dataset_export_jobs.is_none()`.
    pub fn dataset_export_jobs(&self) -> &[crate::types::DatasetExportJobSummary] {
        self.dataset_export_jobs.as_deref().unwrap_or_default()
    }
    /// <p>A token for getting the next set of dataset export jobs (if they exist).</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDatasetExportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDatasetExportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListDatasetExportJobsOutput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsOutput).
    pub fn builder() -> crate::operation::list_dataset_export_jobs::builders::ListDatasetExportJobsOutputBuilder {
        crate::operation::list_dataset_export_jobs::builders::ListDatasetExportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListDatasetExportJobsOutput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDatasetExportJobsOutputBuilder {
    pub(crate) dataset_export_jobs: ::std::option::Option<::std::vec::Vec<crate::types::DatasetExportJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDatasetExportJobsOutputBuilder {
    /// Appends an item to `dataset_export_jobs`.
    ///
    /// To override the contents of this collection use [`set_dataset_export_jobs`](Self::set_dataset_export_jobs).
    ///
    /// <p>The list of dataset export jobs.</p>
    pub fn dataset_export_jobs(mut self, input: crate::types::DatasetExportJobSummary) -> Self {
        let mut v = self.dataset_export_jobs.unwrap_or_default();
        v.push(input);
        self.dataset_export_jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of dataset export jobs.</p>
    pub fn set_dataset_export_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DatasetExportJobSummary>>) -> Self {
        self.dataset_export_jobs = input;
        self
    }
    /// <p>The list of dataset export jobs.</p>
    pub fn get_dataset_export_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DatasetExportJobSummary>> {
        &self.dataset_export_jobs
    }
    /// <p>A token for getting the next set of dataset export jobs (if they exist).</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token for getting the next set of dataset export jobs (if they exist).</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token for getting the next set of dataset export jobs (if they exist).</p>
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
    /// Consumes the builder and constructs a [`ListDatasetExportJobsOutput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsOutput).
    pub fn build(self) -> crate::operation::list_dataset_export_jobs::ListDatasetExportJobsOutput {
        crate::operation::list_dataset_export_jobs::ListDatasetExportJobsOutput {
            dataset_export_jobs: self.dataset_export_jobs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
