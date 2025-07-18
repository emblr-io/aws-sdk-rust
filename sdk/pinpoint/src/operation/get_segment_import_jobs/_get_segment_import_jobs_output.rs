// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSegmentImportJobsOutput {
    /// <p>Provides information about the status and settings of all the import jobs that are associated with an application or segment. An import job is a job that imports endpoint definitions from one or more files.</p>
    pub import_jobs_response: ::std::option::Option<crate::types::ImportJobsResponse>,
    _request_id: Option<String>,
}
impl GetSegmentImportJobsOutput {
    /// <p>Provides information about the status and settings of all the import jobs that are associated with an application or segment. An import job is a job that imports endpoint definitions from one or more files.</p>
    pub fn import_jobs_response(&self) -> ::std::option::Option<&crate::types::ImportJobsResponse> {
        self.import_jobs_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSegmentImportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSegmentImportJobsOutput {
    /// Creates a new builder-style object to manufacture [`GetSegmentImportJobsOutput`](crate::operation::get_segment_import_jobs::GetSegmentImportJobsOutput).
    pub fn builder() -> crate::operation::get_segment_import_jobs::builders::GetSegmentImportJobsOutputBuilder {
        crate::operation::get_segment_import_jobs::builders::GetSegmentImportJobsOutputBuilder::default()
    }
}

/// A builder for [`GetSegmentImportJobsOutput`](crate::operation::get_segment_import_jobs::GetSegmentImportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSegmentImportJobsOutputBuilder {
    pub(crate) import_jobs_response: ::std::option::Option<crate::types::ImportJobsResponse>,
    _request_id: Option<String>,
}
impl GetSegmentImportJobsOutputBuilder {
    /// <p>Provides information about the status and settings of all the import jobs that are associated with an application or segment. An import job is a job that imports endpoint definitions from one or more files.</p>
    /// This field is required.
    pub fn import_jobs_response(mut self, input: crate::types::ImportJobsResponse) -> Self {
        self.import_jobs_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the status and settings of all the import jobs that are associated with an application or segment. An import job is a job that imports endpoint definitions from one or more files.</p>
    pub fn set_import_jobs_response(mut self, input: ::std::option::Option<crate::types::ImportJobsResponse>) -> Self {
        self.import_jobs_response = input;
        self
    }
    /// <p>Provides information about the status and settings of all the import jobs that are associated with an application or segment. An import job is a job that imports endpoint definitions from one or more files.</p>
    pub fn get_import_jobs_response(&self) -> &::std::option::Option<crate::types::ImportJobsResponse> {
        &self.import_jobs_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSegmentImportJobsOutput`](crate::operation::get_segment_import_jobs::GetSegmentImportJobsOutput).
    pub fn build(self) -> crate::operation::get_segment_import_jobs::GetSegmentImportJobsOutput {
        crate::operation::get_segment_import_jobs::GetSegmentImportJobsOutput {
            import_jobs_response: self.import_jobs_response,
            _request_id: self._request_id,
        }
    }
}
