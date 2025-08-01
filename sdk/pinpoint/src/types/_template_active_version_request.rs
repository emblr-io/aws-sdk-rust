// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies which version of a message template to use as the active version of the template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateActiveVersionRequest {
    /// <p>The version of the message template to use as the active version of the template. Valid values are: latest, for the most recent version of the template; or, the unique identifier for any existing version of the template. If you specify an identifier, the value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl TemplateActiveVersionRequest {
    /// <p>The version of the message template to use as the active version of the template. Valid values are: latest, for the most recent version of the template; or, the unique identifier for any existing version of the template. If you specify an identifier, the value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl TemplateActiveVersionRequest {
    /// Creates a new builder-style object to manufacture [`TemplateActiveVersionRequest`](crate::types::TemplateActiveVersionRequest).
    pub fn builder() -> crate::types::builders::TemplateActiveVersionRequestBuilder {
        crate::types::builders::TemplateActiveVersionRequestBuilder::default()
    }
}

/// A builder for [`TemplateActiveVersionRequest`](crate::types::TemplateActiveVersionRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateActiveVersionRequestBuilder {
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl TemplateActiveVersionRequestBuilder {
    /// <p>The version of the message template to use as the active version of the template. Valid values are: latest, for the most recent version of the template; or, the unique identifier for any existing version of the template. If you specify an identifier, the value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the message template to use as the active version of the template. Valid values are: latest, for the most recent version of the template; or, the unique identifier for any existing version of the template. If you specify an identifier, the value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the message template to use as the active version of the template. Valid values are: latest, for the most recent version of the template; or, the unique identifier for any existing version of the template. If you specify an identifier, the value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`TemplateActiveVersionRequest`](crate::types::TemplateActiveVersionRequest).
    pub fn build(self) -> crate::types::TemplateActiveVersionRequest {
        crate::types::TemplateActiveVersionRequest { version: self.version }
    }
}
