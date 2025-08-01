// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a variable in the prompt.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PromptInputVariable {
    /// <p>The name of the variable.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl PromptInputVariable {
    /// <p>The name of the variable.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl PromptInputVariable {
    /// Creates a new builder-style object to manufacture [`PromptInputVariable`](crate::types::PromptInputVariable).
    pub fn builder() -> crate::types::builders::PromptInputVariableBuilder {
        crate::types::builders::PromptInputVariableBuilder::default()
    }
}

/// A builder for [`PromptInputVariable`](crate::types::PromptInputVariable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PromptInputVariableBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl PromptInputVariableBuilder {
    /// <p>The name of the variable.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the variable.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the variable.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`PromptInputVariable`](crate::types::PromptInputVariable).
    pub fn build(self) -> crate::types::PromptInputVariable {
        crate::types::PromptInputVariable { name: self.name }
    }
}
