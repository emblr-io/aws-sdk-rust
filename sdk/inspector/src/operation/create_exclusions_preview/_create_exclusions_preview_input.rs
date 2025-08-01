// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateExclusionsPreviewInput {
    /// <p>The ARN that specifies the assessment template for which you want to create an exclusions preview.</p>
    pub assessment_template_arn: ::std::option::Option<::std::string::String>,
}
impl CreateExclusionsPreviewInput {
    /// <p>The ARN that specifies the assessment template for which you want to create an exclusions preview.</p>
    pub fn assessment_template_arn(&self) -> ::std::option::Option<&str> {
        self.assessment_template_arn.as_deref()
    }
}
impl CreateExclusionsPreviewInput {
    /// Creates a new builder-style object to manufacture [`CreateExclusionsPreviewInput`](crate::operation::create_exclusions_preview::CreateExclusionsPreviewInput).
    pub fn builder() -> crate::operation::create_exclusions_preview::builders::CreateExclusionsPreviewInputBuilder {
        crate::operation::create_exclusions_preview::builders::CreateExclusionsPreviewInputBuilder::default()
    }
}

/// A builder for [`CreateExclusionsPreviewInput`](crate::operation::create_exclusions_preview::CreateExclusionsPreviewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateExclusionsPreviewInputBuilder {
    pub(crate) assessment_template_arn: ::std::option::Option<::std::string::String>,
}
impl CreateExclusionsPreviewInputBuilder {
    /// <p>The ARN that specifies the assessment template for which you want to create an exclusions preview.</p>
    /// This field is required.
    pub fn assessment_template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assessment_template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN that specifies the assessment template for which you want to create an exclusions preview.</p>
    pub fn set_assessment_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assessment_template_arn = input;
        self
    }
    /// <p>The ARN that specifies the assessment template for which you want to create an exclusions preview.</p>
    pub fn get_assessment_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.assessment_template_arn
    }
    /// Consumes the builder and constructs a [`CreateExclusionsPreviewInput`](crate::operation::create_exclusions_preview::CreateExclusionsPreviewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_exclusions_preview::CreateExclusionsPreviewInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_exclusions_preview::CreateExclusionsPreviewInput {
            assessment_template_arn: self.assessment_template_arn,
        })
    }
}
