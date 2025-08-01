// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMedicalScribeJobOutput {
    /// <p>Provides detailed information about the specified Medical Scribe job, including job status and, if applicable, failure reason</p>
    pub medical_scribe_job: ::std::option::Option<crate::types::MedicalScribeJob>,
    _request_id: Option<String>,
}
impl GetMedicalScribeJobOutput {
    /// <p>Provides detailed information about the specified Medical Scribe job, including job status and, if applicable, failure reason</p>
    pub fn medical_scribe_job(&self) -> ::std::option::Option<&crate::types::MedicalScribeJob> {
        self.medical_scribe_job.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetMedicalScribeJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetMedicalScribeJobOutput {
    /// Creates a new builder-style object to manufacture [`GetMedicalScribeJobOutput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobOutput).
    pub fn builder() -> crate::operation::get_medical_scribe_job::builders::GetMedicalScribeJobOutputBuilder {
        crate::operation::get_medical_scribe_job::builders::GetMedicalScribeJobOutputBuilder::default()
    }
}

/// A builder for [`GetMedicalScribeJobOutput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMedicalScribeJobOutputBuilder {
    pub(crate) medical_scribe_job: ::std::option::Option<crate::types::MedicalScribeJob>,
    _request_id: Option<String>,
}
impl GetMedicalScribeJobOutputBuilder {
    /// <p>Provides detailed information about the specified Medical Scribe job, including job status and, if applicable, failure reason</p>
    pub fn medical_scribe_job(mut self, input: crate::types::MedicalScribeJob) -> Self {
        self.medical_scribe_job = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides detailed information about the specified Medical Scribe job, including job status and, if applicable, failure reason</p>
    pub fn set_medical_scribe_job(mut self, input: ::std::option::Option<crate::types::MedicalScribeJob>) -> Self {
        self.medical_scribe_job = input;
        self
    }
    /// <p>Provides detailed information about the specified Medical Scribe job, including job status and, if applicable, failure reason</p>
    pub fn get_medical_scribe_job(&self) -> &::std::option::Option<crate::types::MedicalScribeJob> {
        &self.medical_scribe_job
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetMedicalScribeJobOutput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobOutput).
    pub fn build(self) -> crate::operation::get_medical_scribe_job::GetMedicalScribeJobOutput {
        crate::operation::get_medical_scribe_job::GetMedicalScribeJobOutput {
            medical_scribe_job: self.medical_scribe_job,
            _request_id: self._request_id,
        }
    }
}
