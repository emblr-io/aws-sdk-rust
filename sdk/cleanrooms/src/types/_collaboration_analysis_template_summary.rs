// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The metadata of the analysis template within a collaboration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CollaborationAnalysisTemplateSummary {
    /// <p>The Amazon Resource Name (ARN) of the analysis template.</p>
    pub arn: ::std::string::String,
    /// <p>The time that the summary of the analysis template in a collaboration was created.</p>
    pub create_time: ::aws_smithy_types::DateTime,
    /// <p>The identifier of the analysis template.</p>
    pub id: ::std::string::String,
    /// <p>The name of the analysis template.</p>
    pub name: ::std::string::String,
    /// <p>The time that the summary of the analysis template in the collaboration was last updated.</p>
    pub update_time: ::aws_smithy_types::DateTime,
    /// <p>The unique ARN for the analysis template’s associated collaboration.</p>
    pub collaboration_arn: ::std::string::String,
    /// <p>A unique identifier for the collaboration that the analysis templates belong to. Currently accepts collaboration ID.</p>
    pub collaboration_id: ::std::string::String,
    /// <p>The identifier used to reference members of the collaboration. Currently only supports Amazon Web Services account ID.</p>
    pub creator_account_id: ::std::string::String,
    /// <p>The description of the analysis template.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl CollaborationAnalysisTemplateSummary {
    /// <p>The Amazon Resource Name (ARN) of the analysis template.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The time that the summary of the analysis template in a collaboration was created.</p>
    pub fn create_time(&self) -> &::aws_smithy_types::DateTime {
        &self.create_time
    }
    /// <p>The identifier of the analysis template.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the analysis template.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The time that the summary of the analysis template in the collaboration was last updated.</p>
    pub fn update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.update_time
    }
    /// <p>The unique ARN for the analysis template’s associated collaboration.</p>
    pub fn collaboration_arn(&self) -> &str {
        use std::ops::Deref;
        self.collaboration_arn.deref()
    }
    /// <p>A unique identifier for the collaboration that the analysis templates belong to. Currently accepts collaboration ID.</p>
    pub fn collaboration_id(&self) -> &str {
        use std::ops::Deref;
        self.collaboration_id.deref()
    }
    /// <p>The identifier used to reference members of the collaboration. Currently only supports Amazon Web Services account ID.</p>
    pub fn creator_account_id(&self) -> &str {
        use std::ops::Deref;
        self.creator_account_id.deref()
    }
    /// <p>The description of the analysis template.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl CollaborationAnalysisTemplateSummary {
    /// Creates a new builder-style object to manufacture [`CollaborationAnalysisTemplateSummary`](crate::types::CollaborationAnalysisTemplateSummary).
    pub fn builder() -> crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder {
        crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::default()
    }
}

/// A builder for [`CollaborationAnalysisTemplateSummary`](crate::types::CollaborationAnalysisTemplateSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CollaborationAnalysisTemplateSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) collaboration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) collaboration_id: ::std::option::Option<::std::string::String>,
    pub(crate) creator_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl CollaborationAnalysisTemplateSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the analysis template.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the analysis template.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the analysis template.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The time that the summary of the analysis template in a collaboration was created.</p>
    /// This field is required.
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the summary of the analysis template in a collaboration was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time that the summary of the analysis template in a collaboration was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The identifier of the analysis template.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the analysis template.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the analysis template.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the analysis template.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the analysis template.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the analysis template.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time that the summary of the analysis template in the collaboration was last updated.</p>
    /// This field is required.
    pub fn update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the summary of the analysis template in the collaboration was last updated.</p>
    pub fn set_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_time = input;
        self
    }
    /// <p>The time that the summary of the analysis template in the collaboration was last updated.</p>
    pub fn get_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_time
    }
    /// <p>The unique ARN for the analysis template’s associated collaboration.</p>
    /// This field is required.
    pub fn collaboration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collaboration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ARN for the analysis template’s associated collaboration.</p>
    pub fn set_collaboration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collaboration_arn = input;
        self
    }
    /// <p>The unique ARN for the analysis template’s associated collaboration.</p>
    pub fn get_collaboration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.collaboration_arn
    }
    /// <p>A unique identifier for the collaboration that the analysis templates belong to. Currently accepts collaboration ID.</p>
    /// This field is required.
    pub fn collaboration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collaboration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the collaboration that the analysis templates belong to. Currently accepts collaboration ID.</p>
    pub fn set_collaboration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collaboration_id = input;
        self
    }
    /// <p>A unique identifier for the collaboration that the analysis templates belong to. Currently accepts collaboration ID.</p>
    pub fn get_collaboration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.collaboration_id
    }
    /// <p>The identifier used to reference members of the collaboration. Currently only supports Amazon Web Services account ID.</p>
    /// This field is required.
    pub fn creator_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier used to reference members of the collaboration. Currently only supports Amazon Web Services account ID.</p>
    pub fn set_creator_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_account_id = input;
        self
    }
    /// <p>The identifier used to reference members of the collaboration. Currently only supports Amazon Web Services account ID.</p>
    pub fn get_creator_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_account_id
    }
    /// <p>The description of the analysis template.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the analysis template.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the analysis template.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`CollaborationAnalysisTemplateSummary`](crate::types::CollaborationAnalysisTemplateSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::arn)
    /// - [`create_time`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::create_time)
    /// - [`id`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::id)
    /// - [`name`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::name)
    /// - [`update_time`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::update_time)
    /// - [`collaboration_arn`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::collaboration_arn)
    /// - [`collaboration_id`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::collaboration_id)
    /// - [`creator_account_id`](crate::types::builders::CollaborationAnalysisTemplateSummaryBuilder::creator_account_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::CollaborationAnalysisTemplateSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CollaborationAnalysisTemplateSummary {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            create_time: self.create_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "create_time",
                    "create_time was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            update_time: self.update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "update_time",
                    "update_time was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            collaboration_arn: self.collaboration_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "collaboration_arn",
                    "collaboration_arn was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            collaboration_id: self.collaboration_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "collaboration_id",
                    "collaboration_id was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            creator_account_id: self.creator_account_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creator_account_id",
                    "creator_account_id was not specified but it is required when building CollaborationAnalysisTemplateSummary",
                )
            })?,
            description: self.description,
        })
    }
}
