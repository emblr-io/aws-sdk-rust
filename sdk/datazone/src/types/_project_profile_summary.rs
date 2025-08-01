// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of a project profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ProjectProfileSummary {
    /// <p>The domain ID of the project profile.</p>
    pub domain_id: ::std::string::String,
    /// <p>The ID of the project profile.</p>
    pub id: ::std::string::String,
    /// <p>The name of a project profile.</p>
    pub name: ::std::string::String,
    /// <p>The description of the project profile.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The status of a project profile.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>The user who created the project profile.</p>
    pub created_by: ::std::string::String,
    /// <p>The timestamp of when the project profile was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which a project profile was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The domain unit ID of the project profile.</p>
    pub domain_unit_id: ::std::option::Option<::std::string::String>,
}
impl ProjectProfileSummary {
    /// <p>The domain ID of the project profile.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The ID of the project profile.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of a project profile.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the project profile.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The status of a project profile.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>The user who created the project profile.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The timestamp of when the project profile was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The timestamp at which a project profile was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The domain unit ID of the project profile.</p>
    pub fn domain_unit_id(&self) -> ::std::option::Option<&str> {
        self.domain_unit_id.as_deref()
    }
}
impl ::std::fmt::Debug for ProjectProfileSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ProjectProfileSummary");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("id", &self.id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("created_by", &self.created_by);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("domain_unit_id", &self.domain_unit_id);
        formatter.finish()
    }
}
impl ProjectProfileSummary {
    /// Creates a new builder-style object to manufacture [`ProjectProfileSummary`](crate::types::ProjectProfileSummary).
    pub fn builder() -> crate::types::builders::ProjectProfileSummaryBuilder {
        crate::types::builders::ProjectProfileSummaryBuilder::default()
    }
}

/// A builder for [`ProjectProfileSummary`](crate::types::ProjectProfileSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ProjectProfileSummaryBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) domain_unit_id: ::std::option::Option<::std::string::String>,
}
impl ProjectProfileSummaryBuilder {
    /// <p>The domain ID of the project profile.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain ID of the project profile.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The domain ID of the project profile.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The ID of the project profile.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the project profile.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the project profile.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of a project profile.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a project profile.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a project profile.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the project profile.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the project profile.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the project profile.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The status of a project profile.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a project profile.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a project profile.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>The user who created the project profile.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who created the project profile.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user who created the project profile.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The timestamp of when the project profile was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the project profile was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the project profile was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp at which a project profile was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which a project profile was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The timestamp at which a project profile was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The domain unit ID of the project profile.</p>
    pub fn domain_unit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_unit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain unit ID of the project profile.</p>
    pub fn set_domain_unit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_unit_id = input;
        self
    }
    /// <p>The domain unit ID of the project profile.</p>
    pub fn get_domain_unit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_unit_id
    }
    /// Consumes the builder and constructs a [`ProjectProfileSummary`](crate::types::ProjectProfileSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_id`](crate::types::builders::ProjectProfileSummaryBuilder::domain_id)
    /// - [`id`](crate::types::builders::ProjectProfileSummaryBuilder::id)
    /// - [`name`](crate::types::builders::ProjectProfileSummaryBuilder::name)
    /// - [`created_by`](crate::types::builders::ProjectProfileSummaryBuilder::created_by)
    pub fn build(self) -> ::std::result::Result<crate::types::ProjectProfileSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProjectProfileSummary {
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building ProjectProfileSummary",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building ProjectProfileSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ProjectProfileSummary",
                )
            })?,
            description: self.description,
            status: self.status,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building ProjectProfileSummary",
                )
            })?,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            domain_unit_id: self.domain_unit_id,
        })
    }
}
impl ::std::fmt::Debug for ProjectProfileSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ProjectProfileSummaryBuilder");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("id", &self.id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("created_by", &self.created_by);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("domain_unit_id", &self.domain_unit_id);
        formatter.finish()
    }
}
