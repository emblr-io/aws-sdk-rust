// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of the metadata form.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct MetadataFormSummary {
    /// <p>The form name of the metadata form.</p>
    pub form_name: ::std::option::Option<::std::string::String>,
    /// <p>The type name of the metadata form.</p>
    pub type_name: ::std::string::String,
    /// <p>The type revision of the metadata form.</p>
    pub type_revision: ::std::string::String,
}
impl MetadataFormSummary {
    /// <p>The form name of the metadata form.</p>
    pub fn form_name(&self) -> ::std::option::Option<&str> {
        self.form_name.as_deref()
    }
    /// <p>The type name of the metadata form.</p>
    pub fn type_name(&self) -> &str {
        use std::ops::Deref;
        self.type_name.deref()
    }
    /// <p>The type revision of the metadata form.</p>
    pub fn type_revision(&self) -> &str {
        use std::ops::Deref;
        self.type_revision.deref()
    }
}
impl ::std::fmt::Debug for MetadataFormSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MetadataFormSummary");
        formatter.field("form_name", &self.form_name);
        formatter.field("type_name", &"*** Sensitive Data Redacted ***");
        formatter.field("type_revision", &self.type_revision);
        formatter.finish()
    }
}
impl MetadataFormSummary {
    /// Creates a new builder-style object to manufacture [`MetadataFormSummary`](crate::types::MetadataFormSummary).
    pub fn builder() -> crate::types::builders::MetadataFormSummaryBuilder {
        crate::types::builders::MetadataFormSummaryBuilder::default()
    }
}

/// A builder for [`MetadataFormSummary`](crate::types::MetadataFormSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct MetadataFormSummaryBuilder {
    pub(crate) form_name: ::std::option::Option<::std::string::String>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) type_revision: ::std::option::Option<::std::string::String>,
}
impl MetadataFormSummaryBuilder {
    /// <p>The form name of the metadata form.</p>
    pub fn form_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.form_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The form name of the metadata form.</p>
    pub fn set_form_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.form_name = input;
        self
    }
    /// <p>The form name of the metadata form.</p>
    pub fn get_form_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.form_name
    }
    /// <p>The type name of the metadata form.</p>
    /// This field is required.
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type name of the metadata form.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The type name of the metadata form.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>The type revision of the metadata form.</p>
    /// This field is required.
    pub fn type_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type revision of the metadata form.</p>
    pub fn set_type_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_revision = input;
        self
    }
    /// <p>The type revision of the metadata form.</p>
    pub fn get_type_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_revision
    }
    /// Consumes the builder and constructs a [`MetadataFormSummary`](crate::types::MetadataFormSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`type_name`](crate::types::builders::MetadataFormSummaryBuilder::type_name)
    /// - [`type_revision`](crate::types::builders::MetadataFormSummaryBuilder::type_revision)
    pub fn build(self) -> ::std::result::Result<crate::types::MetadataFormSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MetadataFormSummary {
            form_name: self.form_name,
            type_name: self.type_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "type_name",
                    "type_name was not specified but it is required when building MetadataFormSummary",
                )
            })?,
            type_revision: self.type_revision.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "type_revision",
                    "type_revision was not specified but it is required when building MetadataFormSummary",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for MetadataFormSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MetadataFormSummaryBuilder");
        formatter.field("form_name", &self.form_name);
        formatter.field("type_name", &"*** Sensitive Data Redacted ***");
        formatter.field("type_revision", &self.type_revision);
        formatter.finish()
    }
}
