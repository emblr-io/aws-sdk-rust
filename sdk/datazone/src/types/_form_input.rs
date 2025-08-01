// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of a metadata form.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct FormInput {
    /// <p>The name of the metadata form.</p>
    pub form_name: ::std::string::String,
    /// <p>The ID of the metadata form type.</p>
    pub type_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The revision of the metadata form type.</p>
    pub type_revision: ::std::option::Option<::std::string::String>,
    /// <p>The content of the metadata form.</p>
    pub content: ::std::option::Option<::std::string::String>,
}
impl FormInput {
    /// <p>The name of the metadata form.</p>
    pub fn form_name(&self) -> &str {
        use std::ops::Deref;
        self.form_name.deref()
    }
    /// <p>The ID of the metadata form type.</p>
    pub fn type_identifier(&self) -> ::std::option::Option<&str> {
        self.type_identifier.as_deref()
    }
    /// <p>The revision of the metadata form type.</p>
    pub fn type_revision(&self) -> ::std::option::Option<&str> {
        self.type_revision.as_deref()
    }
    /// <p>The content of the metadata form.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
}
impl ::std::fmt::Debug for FormInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FormInput");
        formatter.field("form_name", &"*** Sensitive Data Redacted ***");
        formatter.field("type_identifier", &"*** Sensitive Data Redacted ***");
        formatter.field("type_revision", &"*** Sensitive Data Redacted ***");
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl FormInput {
    /// Creates a new builder-style object to manufacture [`FormInput`](crate::types::FormInput).
    pub fn builder() -> crate::types::builders::FormInputBuilder {
        crate::types::builders::FormInputBuilder::default()
    }
}

/// A builder for [`FormInput`](crate::types::FormInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct FormInputBuilder {
    pub(crate) form_name: ::std::option::Option<::std::string::String>,
    pub(crate) type_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) type_revision: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
}
impl FormInputBuilder {
    /// <p>The name of the metadata form.</p>
    /// This field is required.
    pub fn form_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.form_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metadata form.</p>
    pub fn set_form_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.form_name = input;
        self
    }
    /// <p>The name of the metadata form.</p>
    pub fn get_form_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.form_name
    }
    /// <p>The ID of the metadata form type.</p>
    pub fn type_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the metadata form type.</p>
    pub fn set_type_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_identifier = input;
        self
    }
    /// <p>The ID of the metadata form type.</p>
    pub fn get_type_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_identifier
    }
    /// <p>The revision of the metadata form type.</p>
    pub fn type_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision of the metadata form type.</p>
    pub fn set_type_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_revision = input;
        self
    }
    /// <p>The revision of the metadata form type.</p>
    pub fn get_type_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_revision
    }
    /// <p>The content of the metadata form.</p>
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the metadata form.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the metadata form.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Consumes the builder and constructs a [`FormInput`](crate::types::FormInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`form_name`](crate::types::builders::FormInputBuilder::form_name)
    pub fn build(self) -> ::std::result::Result<crate::types::FormInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FormInput {
            form_name: self.form_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "form_name",
                    "form_name was not specified but it is required when building FormInput",
                )
            })?,
            type_identifier: self.type_identifier,
            type_revision: self.type_revision,
            content: self.content,
        })
    }
}
impl ::std::fmt::Debug for FormInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FormInputBuilder");
        formatter.field("form_name", &"*** Sensitive Data Redacted ***");
        formatter.field("type_identifier", &"*** Sensitive Data Redacted ***");
        formatter.field("type_revision", &"*** Sensitive Data Redacted ***");
        formatter.field("content", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
