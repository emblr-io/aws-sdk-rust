// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImportJobOutput {
    /// <p>Provides information about the status and settings of a job that imports endpoint definitions from one or more files. The files can be stored in an Amazon Simple Storage Service (Amazon S3) bucket or uploaded directly from a computer by using the Amazon Pinpoint console.</p>
    pub import_job_response: ::std::option::Option<crate::types::ImportJobResponse>,
    _request_id: Option<String>,
}
impl GetImportJobOutput {
    /// <p>Provides information about the status and settings of a job that imports endpoint definitions from one or more files. The files can be stored in an Amazon Simple Storage Service (Amazon S3) bucket or uploaded directly from a computer by using the Amazon Pinpoint console.</p>
    pub fn import_job_response(&self) -> ::std::option::Option<&crate::types::ImportJobResponse> {
        self.import_job_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetImportJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImportJobOutput {
    /// Creates a new builder-style object to manufacture [`GetImportJobOutput`](crate::operation::get_import_job::GetImportJobOutput).
    pub fn builder() -> crate::operation::get_import_job::builders::GetImportJobOutputBuilder {
        crate::operation::get_import_job::builders::GetImportJobOutputBuilder::default()
    }
}

/// A builder for [`GetImportJobOutput`](crate::operation::get_import_job::GetImportJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImportJobOutputBuilder {
    pub(crate) import_job_response: ::std::option::Option<crate::types::ImportJobResponse>,
    _request_id: Option<String>,
}
impl GetImportJobOutputBuilder {
    /// <p>Provides information about the status and settings of a job that imports endpoint definitions from one or more files. The files can be stored in an Amazon Simple Storage Service (Amazon S3) bucket or uploaded directly from a computer by using the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn import_job_response(mut self, input: crate::types::ImportJobResponse) -> Self {
        self.import_job_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the status and settings of a job that imports endpoint definitions from one or more files. The files can be stored in an Amazon Simple Storage Service (Amazon S3) bucket or uploaded directly from a computer by using the Amazon Pinpoint console.</p>
    pub fn set_import_job_response(mut self, input: ::std::option::Option<crate::types::ImportJobResponse>) -> Self {
        self.import_job_response = input;
        self
    }
    /// <p>Provides information about the status and settings of a job that imports endpoint definitions from one or more files. The files can be stored in an Amazon Simple Storage Service (Amazon S3) bucket or uploaded directly from a computer by using the Amazon Pinpoint console.</p>
    pub fn get_import_job_response(&self) -> &::std::option::Option<crate::types::ImportJobResponse> {
        &self.import_job_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImportJobOutput`](crate::operation::get_import_job::GetImportJobOutput).
    pub fn build(self) -> crate::operation::get_import_job::GetImportJobOutput {
        crate::operation::get_import_job::GetImportJobOutput {
            import_job_response: self.import_job_response,
            _request_id: self._request_id,
        }
    }
}
