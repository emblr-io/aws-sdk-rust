// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the metadata form type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct FormTypeData {
    /// <p>The identifier of the Amazon DataZone domain in which the form type exists.</p>
    pub domain_id: ::std::string::String,
    /// <p>The name of the form type.</p>
    pub name: ::std::string::String,
    /// <p>The revision of the form type.</p>
    pub revision: ::std::string::String,
    /// <p>The model of the form type.</p>
    pub model: ::std::option::Option<crate::types::Model>,
    /// <p>The status of the form type.</p>
    pub status: ::std::option::Option<crate::types::FormTypeStatus>,
    /// <p>The identifier of the project that owns the form type.</p>
    pub owning_project_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon DataZone domain in which the form type was originally created.</p>
    pub origin_domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the project in which the form type was originally created.</p>
    pub origin_project_id: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the metadata form type was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon DataZone user who created teh metadata form type.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>The description of the metadata form type.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The imports specified in the form type.</p>
    pub imports: ::std::option::Option<::std::vec::Vec<crate::types::Import>>,
}
impl FormTypeData {
    /// <p>The identifier of the Amazon DataZone domain in which the form type exists.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The name of the form type.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The revision of the form type.</p>
    pub fn revision(&self) -> &str {
        use std::ops::Deref;
        self.revision.deref()
    }
    /// <p>The model of the form type.</p>
    pub fn model(&self) -> ::std::option::Option<&crate::types::Model> {
        self.model.as_ref()
    }
    /// <p>The status of the form type.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FormTypeStatus> {
        self.status.as_ref()
    }
    /// <p>The identifier of the project that owns the form type.</p>
    pub fn owning_project_id(&self) -> ::std::option::Option<&str> {
        self.owning_project_id.as_deref()
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type was originally created.</p>
    pub fn origin_domain_id(&self) -> ::std::option::Option<&str> {
        self.origin_domain_id.as_deref()
    }
    /// <p>The identifier of the project in which the form type was originally created.</p>
    pub fn origin_project_id(&self) -> ::std::option::Option<&str> {
        self.origin_project_id.as_deref()
    }
    /// <p>The timestamp of when the metadata form type was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Amazon DataZone user who created teh metadata form type.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>The description of the metadata form type.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The imports specified in the form type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.imports.is_none()`.
    pub fn imports(&self) -> &[crate::types::Import] {
        self.imports.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for FormTypeData {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FormTypeData");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("revision", &self.revision);
        formatter.field("model", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("owning_project_id", &self.owning_project_id);
        formatter.field("origin_domain_id", &self.origin_domain_id);
        formatter.field("origin_project_id", &self.origin_project_id);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("imports", &self.imports);
        formatter.finish()
    }
}
impl FormTypeData {
    /// Creates a new builder-style object to manufacture [`FormTypeData`](crate::types::FormTypeData).
    pub fn builder() -> crate::types::builders::FormTypeDataBuilder {
        crate::types::builders::FormTypeDataBuilder::default()
    }
}

/// A builder for [`FormTypeData`](crate::types::FormTypeData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct FormTypeDataBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) revision: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<crate::types::Model>,
    pub(crate) status: ::std::option::Option<crate::types::FormTypeStatus>,
    pub(crate) owning_project_id: ::std::option::Option<::std::string::String>,
    pub(crate) origin_domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) origin_project_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) imports: ::std::option::Option<::std::vec::Vec<crate::types::Import>>,
}
impl FormTypeDataBuilder {
    /// <p>The identifier of the Amazon DataZone domain in which the form type exists.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type exists.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type exists.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The name of the form type.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the form type.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the form type.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The revision of the form type.</p>
    /// This field is required.
    pub fn revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision of the form type.</p>
    pub fn set_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision = input;
        self
    }
    /// <p>The revision of the form type.</p>
    pub fn get_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision
    }
    /// <p>The model of the form type.</p>
    pub fn model(mut self, input: crate::types::Model) -> Self {
        self.model = ::std::option::Option::Some(input);
        self
    }
    /// <p>The model of the form type.</p>
    pub fn set_model(mut self, input: ::std::option::Option<crate::types::Model>) -> Self {
        self.model = input;
        self
    }
    /// <p>The model of the form type.</p>
    pub fn get_model(&self) -> &::std::option::Option<crate::types::Model> {
        &self.model
    }
    /// <p>The status of the form type.</p>
    pub fn status(mut self, input: crate::types::FormTypeStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the form type.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FormTypeStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the form type.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FormTypeStatus> {
        &self.status
    }
    /// <p>The identifier of the project that owns the form type.</p>
    pub fn owning_project_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owning_project_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the project that owns the form type.</p>
    pub fn set_owning_project_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owning_project_id = input;
        self
    }
    /// <p>The identifier of the project that owns the form type.</p>
    pub fn get_owning_project_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owning_project_id
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type was originally created.</p>
    pub fn origin_domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin_domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type was originally created.</p>
    pub fn set_origin_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin_domain_id = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which the form type was originally created.</p>
    pub fn get_origin_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin_domain_id
    }
    /// <p>The identifier of the project in which the form type was originally created.</p>
    pub fn origin_project_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin_project_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the project in which the form type was originally created.</p>
    pub fn set_origin_project_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin_project_id = input;
        self
    }
    /// <p>The identifier of the project in which the form type was originally created.</p>
    pub fn get_origin_project_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin_project_id
    }
    /// <p>The timestamp of when the metadata form type was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the metadata form type was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the metadata form type was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Amazon DataZone user who created teh metadata form type.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon DataZone user who created teh metadata form type.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The Amazon DataZone user who created teh metadata form type.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The description of the metadata form type.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the metadata form type.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the metadata form type.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `imports`.
    ///
    /// To override the contents of this collection use [`set_imports`](Self::set_imports).
    ///
    /// <p>The imports specified in the form type.</p>
    pub fn imports(mut self, input: crate::types::Import) -> Self {
        let mut v = self.imports.unwrap_or_default();
        v.push(input);
        self.imports = ::std::option::Option::Some(v);
        self
    }
    /// <p>The imports specified in the form type.</p>
    pub fn set_imports(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Import>>) -> Self {
        self.imports = input;
        self
    }
    /// <p>The imports specified in the form type.</p>
    pub fn get_imports(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Import>> {
        &self.imports
    }
    /// Consumes the builder and constructs a [`FormTypeData`](crate::types::FormTypeData).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_id`](crate::types::builders::FormTypeDataBuilder::domain_id)
    /// - [`name`](crate::types::builders::FormTypeDataBuilder::name)
    /// - [`revision`](crate::types::builders::FormTypeDataBuilder::revision)
    pub fn build(self) -> ::std::result::Result<crate::types::FormTypeData, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FormTypeData {
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building FormTypeData",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building FormTypeData",
                )
            })?,
            revision: self.revision.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision",
                    "revision was not specified but it is required when building FormTypeData",
                )
            })?,
            model: self.model,
            status: self.status,
            owning_project_id: self.owning_project_id,
            origin_domain_id: self.origin_domain_id,
            origin_project_id: self.origin_project_id,
            created_at: self.created_at,
            created_by: self.created_by,
            description: self.description,
            imports: self.imports,
        })
    }
}
impl ::std::fmt::Debug for FormTypeDataBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FormTypeDataBuilder");
        formatter.field("domain_id", &self.domain_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("revision", &self.revision);
        formatter.field("model", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("owning_project_id", &self.owning_project_id);
        formatter.field("origin_domain_id", &self.origin_domain_id);
        formatter.field("origin_project_id", &self.origin_project_id);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("imports", &self.imports);
        formatter.finish()
    }
}
