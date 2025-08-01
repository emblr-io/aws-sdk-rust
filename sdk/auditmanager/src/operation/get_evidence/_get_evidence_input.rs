// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEvidenceInput {
    /// <p>The unique identifier for the assessment.</p>
    pub assessment_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the control set.</p>
    pub control_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the folder that the evidence is stored in.</p>
    pub evidence_folder_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the evidence.</p>
    pub evidence_id: ::std::option::Option<::std::string::String>,
}
impl GetEvidenceInput {
    /// <p>The unique identifier for the assessment.</p>
    pub fn assessment_id(&self) -> ::std::option::Option<&str> {
        self.assessment_id.as_deref()
    }
    /// <p>The unique identifier for the control set.</p>
    pub fn control_set_id(&self) -> ::std::option::Option<&str> {
        self.control_set_id.as_deref()
    }
    /// <p>The unique identifier for the folder that the evidence is stored in.</p>
    pub fn evidence_folder_id(&self) -> ::std::option::Option<&str> {
        self.evidence_folder_id.as_deref()
    }
    /// <p>The unique identifier for the evidence.</p>
    pub fn evidence_id(&self) -> ::std::option::Option<&str> {
        self.evidence_id.as_deref()
    }
}
impl GetEvidenceInput {
    /// Creates a new builder-style object to manufacture [`GetEvidenceInput`](crate::operation::get_evidence::GetEvidenceInput).
    pub fn builder() -> crate::operation::get_evidence::builders::GetEvidenceInputBuilder {
        crate::operation::get_evidence::builders::GetEvidenceInputBuilder::default()
    }
}

/// A builder for [`GetEvidenceInput`](crate::operation::get_evidence::GetEvidenceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEvidenceInputBuilder {
    pub(crate) assessment_id: ::std::option::Option<::std::string::String>,
    pub(crate) control_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) evidence_folder_id: ::std::option::Option<::std::string::String>,
    pub(crate) evidence_id: ::std::option::Option<::std::string::String>,
}
impl GetEvidenceInputBuilder {
    /// <p>The unique identifier for the assessment.</p>
    /// This field is required.
    pub fn assessment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assessment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn set_assessment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assessment_id = input;
        self
    }
    /// <p>The unique identifier for the assessment.</p>
    pub fn get_assessment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.assessment_id
    }
    /// <p>The unique identifier for the control set.</p>
    /// This field is required.
    pub fn control_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the control set.</p>
    pub fn set_control_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_set_id = input;
        self
    }
    /// <p>The unique identifier for the control set.</p>
    pub fn get_control_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_set_id
    }
    /// <p>The unique identifier for the folder that the evidence is stored in.</p>
    /// This field is required.
    pub fn evidence_folder_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evidence_folder_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the folder that the evidence is stored in.</p>
    pub fn set_evidence_folder_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evidence_folder_id = input;
        self
    }
    /// <p>The unique identifier for the folder that the evidence is stored in.</p>
    pub fn get_evidence_folder_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.evidence_folder_id
    }
    /// <p>The unique identifier for the evidence.</p>
    /// This field is required.
    pub fn evidence_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evidence_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the evidence.</p>
    pub fn set_evidence_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evidence_id = input;
        self
    }
    /// <p>The unique identifier for the evidence.</p>
    pub fn get_evidence_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.evidence_id
    }
    /// Consumes the builder and constructs a [`GetEvidenceInput`](crate::operation::get_evidence::GetEvidenceInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_evidence::GetEvidenceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_evidence::GetEvidenceInput {
            assessment_id: self.assessment_id,
            control_set_id: self.control_set_id,
            evidence_folder_id: self.evidence_folder_id,
            evidence_id: self.evidence_id,
        })
    }
}
