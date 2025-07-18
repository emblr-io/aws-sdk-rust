// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about an email template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EmailTemplateMetadata {
    /// <p>The name of the template.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The time and date the template was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EmailTemplateMetadata {
    /// <p>The name of the template.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The time and date the template was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
}
impl EmailTemplateMetadata {
    /// Creates a new builder-style object to manufacture [`EmailTemplateMetadata`](crate::types::EmailTemplateMetadata).
    pub fn builder() -> crate::types::builders::EmailTemplateMetadataBuilder {
        crate::types::builders::EmailTemplateMetadataBuilder::default()
    }
}

/// A builder for [`EmailTemplateMetadata`](crate::types::EmailTemplateMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EmailTemplateMetadataBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EmailTemplateMetadataBuilder {
    /// <p>The name of the template.</p>
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the template.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the template.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The time and date the template was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time and date the template was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The time and date the template was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// Consumes the builder and constructs a [`EmailTemplateMetadata`](crate::types::EmailTemplateMetadata).
    pub fn build(self) -> crate::types::EmailTemplateMetadata {
        crate::types::EmailTemplateMetadata {
            template_name: self.template_name,
            created_timestamp: self.created_timestamp,
        }
    }
}
