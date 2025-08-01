// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMedicalScribeJobInput {
    /// <p>The name of the Medical Scribe job you want information about. Job names are case sensitive.</p>
    pub medical_scribe_job_name: ::std::option::Option<::std::string::String>,
}
impl GetMedicalScribeJobInput {
    /// <p>The name of the Medical Scribe job you want information about. Job names are case sensitive.</p>
    pub fn medical_scribe_job_name(&self) -> ::std::option::Option<&str> {
        self.medical_scribe_job_name.as_deref()
    }
}
impl GetMedicalScribeJobInput {
    /// Creates a new builder-style object to manufacture [`GetMedicalScribeJobInput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobInput).
    pub fn builder() -> crate::operation::get_medical_scribe_job::builders::GetMedicalScribeJobInputBuilder {
        crate::operation::get_medical_scribe_job::builders::GetMedicalScribeJobInputBuilder::default()
    }
}

/// A builder for [`GetMedicalScribeJobInput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMedicalScribeJobInputBuilder {
    pub(crate) medical_scribe_job_name: ::std::option::Option<::std::string::String>,
}
impl GetMedicalScribeJobInputBuilder {
    /// <p>The name of the Medical Scribe job you want information about. Job names are case sensitive.</p>
    /// This field is required.
    pub fn medical_scribe_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.medical_scribe_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Medical Scribe job you want information about. Job names are case sensitive.</p>
    pub fn set_medical_scribe_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.medical_scribe_job_name = input;
        self
    }
    /// <p>The name of the Medical Scribe job you want information about. Job names are case sensitive.</p>
    pub fn get_medical_scribe_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.medical_scribe_job_name
    }
    /// Consumes the builder and constructs a [`GetMedicalScribeJobInput`](crate::operation::get_medical_scribe_job::GetMedicalScribeJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_medical_scribe_job::GetMedicalScribeJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_medical_scribe_job::GetMedicalScribeJobInput {
            medical_scribe_job_name: self.medical_scribe_job_name,
        })
    }
}
