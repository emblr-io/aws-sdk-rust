// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAssessmentRunInput {
    /// <p>The ARN that specifies the assessment run that you want to delete.</p>
    pub assessment_run_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteAssessmentRunInput {
    /// <p>The ARN that specifies the assessment run that you want to delete.</p>
    pub fn assessment_run_arn(&self) -> ::std::option::Option<&str> {
        self.assessment_run_arn.as_deref()
    }
}
impl DeleteAssessmentRunInput {
    /// Creates a new builder-style object to manufacture [`DeleteAssessmentRunInput`](crate::operation::delete_assessment_run::DeleteAssessmentRunInput).
    pub fn builder() -> crate::operation::delete_assessment_run::builders::DeleteAssessmentRunInputBuilder {
        crate::operation::delete_assessment_run::builders::DeleteAssessmentRunInputBuilder::default()
    }
}

/// A builder for [`DeleteAssessmentRunInput`](crate::operation::delete_assessment_run::DeleteAssessmentRunInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAssessmentRunInputBuilder {
    pub(crate) assessment_run_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteAssessmentRunInputBuilder {
    /// <p>The ARN that specifies the assessment run that you want to delete.</p>
    /// This field is required.
    pub fn assessment_run_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assessment_run_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN that specifies the assessment run that you want to delete.</p>
    pub fn set_assessment_run_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assessment_run_arn = input;
        self
    }
    /// <p>The ARN that specifies the assessment run that you want to delete.</p>
    pub fn get_assessment_run_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.assessment_run_arn
    }
    /// Consumes the builder and constructs a [`DeleteAssessmentRunInput`](crate::operation::delete_assessment_run::DeleteAssessmentRunInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_assessment_run::DeleteAssessmentRunInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_assessment_run::DeleteAssessmentRunInput {
            assessment_run_arn: self.assessment_run_arn,
        })
    }
}
