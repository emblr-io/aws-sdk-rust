// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about an evaluation form.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluationFormSummary {
    /// <p>The unique identifier for the evaluation form.</p>
    pub evaluation_form_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) for the evaluation form resource.</p>
    pub evaluation_form_arn: ::std::string::String,
    /// <p>A title of the evaluation form.</p>
    pub title: ::std::string::String,
    /// <p>The timestamp for when the evaluation form was created.</p>
    pub created_time: ::aws_smithy_types::DateTime,
    /// <p>The Amazon Resource Name (ARN) of the user who created the evaluation form.</p>
    pub created_by: ::std::string::String,
    /// <p>The timestamp for when the evaluation form was last updated.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the evaluation form.</p>
    pub last_modified_by: ::std::string::String,
    /// <p>The timestamp for when the evaluation form was last activated.</p>
    pub last_activated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of the user who last activated the evaluation form.</p>
    pub last_activated_by: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the latest evaluation form version.</p>
    pub latest_version: i32,
    /// <p>The version of the active evaluation form version.</p>
    pub active_version: ::std::option::Option<i32>,
}
impl EvaluationFormSummary {
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn evaluation_form_id(&self) -> &str {
        use std::ops::Deref;
        self.evaluation_form_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the evaluation form resource.</p>
    pub fn evaluation_form_arn(&self) -> &str {
        use std::ops::Deref;
        self.evaluation_form_arn.deref()
    }
    /// <p>A title of the evaluation form.</p>
    pub fn title(&self) -> &str {
        use std::ops::Deref;
        self.title.deref()
    }
    /// <p>The timestamp for when the evaluation form was created.</p>
    pub fn created_time(&self) -> &::aws_smithy_types::DateTime {
        &self.created_time
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the evaluation form.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The timestamp for when the evaluation form was last updated.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the evaluation form.</p>
    pub fn last_modified_by(&self) -> &str {
        use std::ops::Deref;
        self.last_modified_by.deref()
    }
    /// <p>The timestamp for when the evaluation form was last activated.</p>
    pub fn last_activated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_activated_time.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last activated the evaluation form.</p>
    pub fn last_activated_by(&self) -> ::std::option::Option<&str> {
        self.last_activated_by.as_deref()
    }
    /// <p>The version number of the latest evaluation form version.</p>
    pub fn latest_version(&self) -> i32 {
        self.latest_version
    }
    /// <p>The version of the active evaluation form version.</p>
    pub fn active_version(&self) -> ::std::option::Option<i32> {
        self.active_version
    }
}
impl EvaluationFormSummary {
    /// Creates a new builder-style object to manufacture [`EvaluationFormSummary`](crate::types::EvaluationFormSummary).
    pub fn builder() -> crate::types::builders::EvaluationFormSummaryBuilder {
        crate::types::builders::EvaluationFormSummaryBuilder::default()
    }
}

/// A builder for [`EvaluationFormSummary`](crate::types::EvaluationFormSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluationFormSummaryBuilder {
    pub(crate) evaluation_form_id: ::std::option::Option<::std::string::String>,
    pub(crate) evaluation_form_arn: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_by: ::std::option::Option<::std::string::String>,
    pub(crate) last_activated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_activated_by: ::std::option::Option<::std::string::String>,
    pub(crate) latest_version: ::std::option::Option<i32>,
    pub(crate) active_version: ::std::option::Option<i32>,
}
impl EvaluationFormSummaryBuilder {
    /// <p>The unique identifier for the evaluation form.</p>
    /// This field is required.
    pub fn evaluation_form_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evaluation_form_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn set_evaluation_form_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evaluation_form_id = input;
        self
    }
    /// <p>The unique identifier for the evaluation form.</p>
    pub fn get_evaluation_form_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.evaluation_form_id
    }
    /// <p>The Amazon Resource Name (ARN) for the evaluation form resource.</p>
    /// This field is required.
    pub fn evaluation_form_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.evaluation_form_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the evaluation form resource.</p>
    pub fn set_evaluation_form_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.evaluation_form_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the evaluation form resource.</p>
    pub fn get_evaluation_form_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.evaluation_form_arn
    }
    /// <p>A title of the evaluation form.</p>
    /// This field is required.
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A title of the evaluation form.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>A title of the evaluation form.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The timestamp for when the evaluation form was created.</p>
    /// This field is required.
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the evaluation form was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The timestamp for when the evaluation form was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the evaluation form.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the evaluation form.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who created the evaluation form.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The timestamp for when the evaluation form was last updated.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the evaluation form was last updated.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp for when the evaluation form was last updated.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the evaluation form.</p>
    /// This field is required.
    pub fn last_modified_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the evaluation form.</p>
    pub fn set_last_modified_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_by = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the evaluation form.</p>
    pub fn get_last_modified_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_by
    }
    /// <p>The timestamp for when the evaluation form was last activated.</p>
    pub fn last_activated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_activated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the evaluation form was last activated.</p>
    pub fn set_last_activated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_activated_time = input;
        self
    }
    /// <p>The timestamp for when the evaluation form was last activated.</p>
    pub fn get_last_activated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_activated_time
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last activated the evaluation form.</p>
    pub fn last_activated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_activated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last activated the evaluation form.</p>
    pub fn set_last_activated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_activated_by = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last activated the evaluation form.</p>
    pub fn get_last_activated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_activated_by
    }
    /// <p>The version number of the latest evaluation form version.</p>
    /// This field is required.
    pub fn latest_version(mut self, input: i32) -> Self {
        self.latest_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the latest evaluation form version.</p>
    pub fn set_latest_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.latest_version = input;
        self
    }
    /// <p>The version number of the latest evaluation form version.</p>
    pub fn get_latest_version(&self) -> &::std::option::Option<i32> {
        &self.latest_version
    }
    /// <p>The version of the active evaluation form version.</p>
    pub fn active_version(mut self, input: i32) -> Self {
        self.active_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the active evaluation form version.</p>
    pub fn set_active_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.active_version = input;
        self
    }
    /// <p>The version of the active evaluation form version.</p>
    pub fn get_active_version(&self) -> &::std::option::Option<i32> {
        &self.active_version
    }
    /// Consumes the builder and constructs a [`EvaluationFormSummary`](crate::types::EvaluationFormSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`evaluation_form_id`](crate::types::builders::EvaluationFormSummaryBuilder::evaluation_form_id)
    /// - [`evaluation_form_arn`](crate::types::builders::EvaluationFormSummaryBuilder::evaluation_form_arn)
    /// - [`title`](crate::types::builders::EvaluationFormSummaryBuilder::title)
    /// - [`created_time`](crate::types::builders::EvaluationFormSummaryBuilder::created_time)
    /// - [`created_by`](crate::types::builders::EvaluationFormSummaryBuilder::created_by)
    /// - [`last_modified_time`](crate::types::builders::EvaluationFormSummaryBuilder::last_modified_time)
    /// - [`last_modified_by`](crate::types::builders::EvaluationFormSummaryBuilder::last_modified_by)
    pub fn build(self) -> ::std::result::Result<crate::types::EvaluationFormSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EvaluationFormSummary {
            evaluation_form_id: self.evaluation_form_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "evaluation_form_id",
                    "evaluation_form_id was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            evaluation_form_arn: self.evaluation_form_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "evaluation_form_arn",
                    "evaluation_form_arn was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            title: self.title.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "title",
                    "title was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            created_time: self.created_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_time",
                    "created_time was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            last_modified_by: self.last_modified_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_by",
                    "last_modified_by was not specified but it is required when building EvaluationFormSummary",
                )
            })?,
            last_activated_time: self.last_activated_time,
            last_activated_by: self.last_activated_by,
            latest_version: self.latest_version.unwrap_or_default(),
            active_version: self.active_version,
        })
    }
}
