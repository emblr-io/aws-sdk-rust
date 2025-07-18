// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input for an agent collaborator. The input can be text or an action invocation result.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AgentCollaboratorInputPayload {
    /// <p>The input type.</p>
    pub r#type: ::std::option::Option<crate::types::PayloadType>,
    /// <p>Input text.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>An action invocation result.</p>
    pub return_control_results: ::std::option::Option<crate::types::ReturnControlResults>,
}
impl AgentCollaboratorInputPayload {
    /// <p>The input type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::PayloadType> {
        self.r#type.as_ref()
    }
    /// <p>Input text.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>An action invocation result.</p>
    pub fn return_control_results(&self) -> ::std::option::Option<&crate::types::ReturnControlResults> {
        self.return_control_results.as_ref()
    }
}
impl ::std::fmt::Debug for AgentCollaboratorInputPayload {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AgentCollaboratorInputPayload");
        formatter.field("r#type", &self.r#type);
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("return_control_results", &self.return_control_results);
        formatter.finish()
    }
}
impl AgentCollaboratorInputPayload {
    /// Creates a new builder-style object to manufacture [`AgentCollaboratorInputPayload`](crate::types::AgentCollaboratorInputPayload).
    pub fn builder() -> crate::types::builders::AgentCollaboratorInputPayloadBuilder {
        crate::types::builders::AgentCollaboratorInputPayloadBuilder::default()
    }
}

/// A builder for [`AgentCollaboratorInputPayload`](crate::types::AgentCollaboratorInputPayload).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AgentCollaboratorInputPayloadBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::PayloadType>,
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) return_control_results: ::std::option::Option<crate::types::ReturnControlResults>,
}
impl AgentCollaboratorInputPayloadBuilder {
    /// <p>The input type.</p>
    pub fn r#type(mut self, input: crate::types::PayloadType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::PayloadType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The input type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::PayloadType> {
        &self.r#type
    }
    /// <p>Input text.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Input text.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>Input text.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>An action invocation result.</p>
    pub fn return_control_results(mut self, input: crate::types::ReturnControlResults) -> Self {
        self.return_control_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>An action invocation result.</p>
    pub fn set_return_control_results(mut self, input: ::std::option::Option<crate::types::ReturnControlResults>) -> Self {
        self.return_control_results = input;
        self
    }
    /// <p>An action invocation result.</p>
    pub fn get_return_control_results(&self) -> &::std::option::Option<crate::types::ReturnControlResults> {
        &self.return_control_results
    }
    /// Consumes the builder and constructs a [`AgentCollaboratorInputPayload`](crate::types::AgentCollaboratorInputPayload).
    pub fn build(self) -> crate::types::AgentCollaboratorInputPayload {
        crate::types::AgentCollaboratorInputPayload {
            r#type: self.r#type,
            text: self.text,
            return_control_results: self.return_control_results,
        }
    }
}
impl ::std::fmt::Debug for AgentCollaboratorInputPayloadBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AgentCollaboratorInputPayloadBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("return_control_results", &self.return_control_results);
        formatter.finish()
    }
}
