// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDicomImportJobsOutput {
    /// <p>A list of job summaries.</p>
    pub job_summaries: ::std::vec::Vec<crate::types::DicomImportJobSummary>,
    /// <p>The pagination token used to retrieve the list of import jobs on the next page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDicomImportJobsOutput {
    /// <p>A list of job summaries.</p>
    pub fn job_summaries(&self) -> &[crate::types::DicomImportJobSummary] {
        use std::ops::Deref;
        self.job_summaries.deref()
    }
    /// <p>The pagination token used to retrieve the list of import jobs on the next page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDicomImportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDicomImportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListDicomImportJobsOutput`](crate::operation::list_dicom_import_jobs::ListDicomImportJobsOutput).
    pub fn builder() -> crate::operation::list_dicom_import_jobs::builders::ListDicomImportJobsOutputBuilder {
        crate::operation::list_dicom_import_jobs::builders::ListDicomImportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListDicomImportJobsOutput`](crate::operation::list_dicom_import_jobs::ListDicomImportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDicomImportJobsOutputBuilder {
    pub(crate) job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::DicomImportJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDicomImportJobsOutputBuilder {
    /// Appends an item to `job_summaries`.
    ///
    /// To override the contents of this collection use [`set_job_summaries`](Self::set_job_summaries).
    ///
    /// <p>A list of job summaries.</p>
    pub fn job_summaries(mut self, input: crate::types::DicomImportJobSummary) -> Self {
        let mut v = self.job_summaries.unwrap_or_default();
        v.push(input);
        self.job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of job summaries.</p>
    pub fn set_job_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DicomImportJobSummary>>) -> Self {
        self.job_summaries = input;
        self
    }
    /// <p>A list of job summaries.</p>
    pub fn get_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DicomImportJobSummary>> {
        &self.job_summaries
    }
    /// <p>The pagination token used to retrieve the list of import jobs on the next page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token used to retrieve the list of import jobs on the next page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token used to retrieve the list of import jobs on the next page.</p>
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
    /// Consumes the builder and constructs a [`ListDicomImportJobsOutput`](crate::operation::list_dicom_import_jobs::ListDicomImportJobsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_summaries`](crate::operation::list_dicom_import_jobs::builders::ListDicomImportJobsOutputBuilder::job_summaries)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_dicom_import_jobs::ListDicomImportJobsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_dicom_import_jobs::ListDicomImportJobsOutput {
            job_summaries: self.job_summaries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_summaries",
                    "job_summaries was not specified but it is required when building ListDicomImportJobsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
