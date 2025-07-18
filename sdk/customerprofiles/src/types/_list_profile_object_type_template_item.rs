// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A ProfileObjectTypeTemplate in a list of ProfileObjectTypeTemplates.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProfileObjectTypeTemplateItem {
    /// <p>A unique identifier for the object template.</p>
    pub template_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the source of the object template.</p>
    pub source_name: ::std::option::Option<::std::string::String>,
    /// <p>The source of the object template.</p>
    pub source_object: ::std::option::Option<::std::string::String>,
}
impl ListProfileObjectTypeTemplateItem {
    /// <p>A unique identifier for the object template.</p>
    pub fn template_id(&self) -> ::std::option::Option<&str> {
        self.template_id.as_deref()
    }
    /// <p>The name of the source of the object template.</p>
    pub fn source_name(&self) -> ::std::option::Option<&str> {
        self.source_name.as_deref()
    }
    /// <p>The source of the object template.</p>
    pub fn source_object(&self) -> ::std::option::Option<&str> {
        self.source_object.as_deref()
    }
}
impl ListProfileObjectTypeTemplateItem {
    /// Creates a new builder-style object to manufacture [`ListProfileObjectTypeTemplateItem`](crate::types::ListProfileObjectTypeTemplateItem).
    pub fn builder() -> crate::types::builders::ListProfileObjectTypeTemplateItemBuilder {
        crate::types::builders::ListProfileObjectTypeTemplateItemBuilder::default()
    }
}

/// A builder for [`ListProfileObjectTypeTemplateItem`](crate::types::ListProfileObjectTypeTemplateItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProfileObjectTypeTemplateItemBuilder {
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_object: ::std::option::Option<::std::string::String>,
}
impl ListProfileObjectTypeTemplateItemBuilder {
    /// <p>A unique identifier for the object template.</p>
    pub fn template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the object template.</p>
    pub fn set_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_id = input;
        self
    }
    /// <p>A unique identifier for the object template.</p>
    pub fn get_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_id
    }
    /// <p>The name of the source of the object template.</p>
    pub fn source_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source of the object template.</p>
    pub fn set_source_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_name = input;
        self
    }
    /// <p>The name of the source of the object template.</p>
    pub fn get_source_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_name
    }
    /// <p>The source of the object template.</p>
    pub fn source_object(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_object = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source of the object template.</p>
    pub fn set_source_object(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_object = input;
        self
    }
    /// <p>The source of the object template.</p>
    pub fn get_source_object(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_object
    }
    /// Consumes the builder and constructs a [`ListProfileObjectTypeTemplateItem`](crate::types::ListProfileObjectTypeTemplateItem).
    pub fn build(self) -> crate::types::ListProfileObjectTypeTemplateItem {
        crate::types::ListProfileObjectTypeTemplateItem {
            template_id: self.template_id,
            source_name: self.source_name,
            source_object: self.source_object,
        }
    }
}
