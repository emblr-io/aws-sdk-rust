// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The identifier of the task template field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskTemplateFieldIdentifier {
    /// <p>The name of the task template field.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl TaskTemplateFieldIdentifier {
    /// <p>The name of the task template field.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl TaskTemplateFieldIdentifier {
    /// Creates a new builder-style object to manufacture [`TaskTemplateFieldIdentifier`](crate::types::TaskTemplateFieldIdentifier).
    pub fn builder() -> crate::types::builders::TaskTemplateFieldIdentifierBuilder {
        crate::types::builders::TaskTemplateFieldIdentifierBuilder::default()
    }
}

/// A builder for [`TaskTemplateFieldIdentifier`](crate::types::TaskTemplateFieldIdentifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskTemplateFieldIdentifierBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl TaskTemplateFieldIdentifierBuilder {
    /// <p>The name of the task template field.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the task template field.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the task template field.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`TaskTemplateFieldIdentifier`](crate::types::TaskTemplateFieldIdentifier).
    pub fn build(self) -> crate::types::TaskTemplateFieldIdentifier {
        crate::types::TaskTemplateFieldIdentifier { name: self.name }
    }
}
