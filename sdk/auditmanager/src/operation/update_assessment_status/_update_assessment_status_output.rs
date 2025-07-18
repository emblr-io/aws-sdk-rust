// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAssessmentStatusOutput {
    /// <p>The name of the updated assessment that the <code>UpdateAssessmentStatus</code> API returned.</p>
    pub assessment: ::std::option::Option<crate::types::Assessment>,
    _request_id: Option<String>,
}
impl UpdateAssessmentStatusOutput {
    /// <p>The name of the updated assessment that the <code>UpdateAssessmentStatus</code> API returned.</p>
    pub fn assessment(&self) -> ::std::option::Option<&crate::types::Assessment> {
        self.assessment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateAssessmentStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateAssessmentStatusOutput {
    /// Creates a new builder-style object to manufacture [`UpdateAssessmentStatusOutput`](crate::operation::update_assessment_status::UpdateAssessmentStatusOutput).
    pub fn builder() -> crate::operation::update_assessment_status::builders::UpdateAssessmentStatusOutputBuilder {
        crate::operation::update_assessment_status::builders::UpdateAssessmentStatusOutputBuilder::default()
    }
}

/// A builder for [`UpdateAssessmentStatusOutput`](crate::operation::update_assessment_status::UpdateAssessmentStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAssessmentStatusOutputBuilder {
    pub(crate) assessment: ::std::option::Option<crate::types::Assessment>,
    _request_id: Option<String>,
}
impl UpdateAssessmentStatusOutputBuilder {
    /// <p>The name of the updated assessment that the <code>UpdateAssessmentStatus</code> API returned.</p>
    pub fn assessment(mut self, input: crate::types::Assessment) -> Self {
        self.assessment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the updated assessment that the <code>UpdateAssessmentStatus</code> API returned.</p>
    pub fn set_assessment(mut self, input: ::std::option::Option<crate::types::Assessment>) -> Self {
        self.assessment = input;
        self
    }
    /// <p>The name of the updated assessment that the <code>UpdateAssessmentStatus</code> API returned.</p>
    pub fn get_assessment(&self) -> &::std::option::Option<crate::types::Assessment> {
        &self.assessment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateAssessmentStatusOutput`](crate::operation::update_assessment_status::UpdateAssessmentStatusOutput).
    pub fn build(self) -> crate::operation::update_assessment_status::UpdateAssessmentStatusOutput {
        crate::operation::update_assessment_status::UpdateAssessmentStatusOutput {
            assessment: self.assessment,
            _request_id: self._request_id,
        }
    }
}
