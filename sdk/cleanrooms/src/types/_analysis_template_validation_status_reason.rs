// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The reasons for the validation results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalysisTemplateValidationStatusReason {
    /// <p>The validation message.</p>
    pub message: ::std::string::String,
}
impl AnalysisTemplateValidationStatusReason {
    /// <p>The validation message.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl AnalysisTemplateValidationStatusReason {
    /// Creates a new builder-style object to manufacture [`AnalysisTemplateValidationStatusReason`](crate::types::AnalysisTemplateValidationStatusReason).
    pub fn builder() -> crate::types::builders::AnalysisTemplateValidationStatusReasonBuilder {
        crate::types::builders::AnalysisTemplateValidationStatusReasonBuilder::default()
    }
}

/// A builder for [`AnalysisTemplateValidationStatusReason`](crate::types::AnalysisTemplateValidationStatusReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalysisTemplateValidationStatusReasonBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl AnalysisTemplateValidationStatusReasonBuilder {
    /// <p>The validation message.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The validation message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The validation message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`AnalysisTemplateValidationStatusReason`](crate::types::AnalysisTemplateValidationStatusReason).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::builders::AnalysisTemplateValidationStatusReasonBuilder::message)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::AnalysisTemplateValidationStatusReason, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalysisTemplateValidationStatusReason {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building AnalysisTemplateValidationStatusReason",
                )
            })?,
        })
    }
}
