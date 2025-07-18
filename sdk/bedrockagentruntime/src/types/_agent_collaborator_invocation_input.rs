// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An agent collaborator invocation input.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AgentCollaboratorInvocationInput {
    /// <p>The collaborator's name.</p>
    pub agent_collaborator_name: ::std::option::Option<::std::string::String>,
    /// <p>The collaborator's alias ARN.</p>
    pub agent_collaborator_alias_arn: ::std::option::Option<::std::string::String>,
    /// <p>Text or action invocation result input for the collaborator.</p>
    pub input: ::std::option::Option<crate::types::AgentCollaboratorInputPayload>,
}
impl AgentCollaboratorInvocationInput {
    /// <p>The collaborator's name.</p>
    pub fn agent_collaborator_name(&self) -> ::std::option::Option<&str> {
        self.agent_collaborator_name.as_deref()
    }
    /// <p>The collaborator's alias ARN.</p>
    pub fn agent_collaborator_alias_arn(&self) -> ::std::option::Option<&str> {
        self.agent_collaborator_alias_arn.as_deref()
    }
    /// <p>Text or action invocation result input for the collaborator.</p>
    pub fn input(&self) -> ::std::option::Option<&crate::types::AgentCollaboratorInputPayload> {
        self.input.as_ref()
    }
}
impl AgentCollaboratorInvocationInput {
    /// Creates a new builder-style object to manufacture [`AgentCollaboratorInvocationInput`](crate::types::AgentCollaboratorInvocationInput).
    pub fn builder() -> crate::types::builders::AgentCollaboratorInvocationInputBuilder {
        crate::types::builders::AgentCollaboratorInvocationInputBuilder::default()
    }
}

/// A builder for [`AgentCollaboratorInvocationInput`](crate::types::AgentCollaboratorInvocationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AgentCollaboratorInvocationInputBuilder {
    pub(crate) agent_collaborator_name: ::std::option::Option<::std::string::String>,
    pub(crate) agent_collaborator_alias_arn: ::std::option::Option<::std::string::String>,
    pub(crate) input: ::std::option::Option<crate::types::AgentCollaboratorInputPayload>,
}
impl AgentCollaboratorInvocationInputBuilder {
    /// <p>The collaborator's name.</p>
    pub fn agent_collaborator_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_collaborator_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The collaborator's name.</p>
    pub fn set_agent_collaborator_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_collaborator_name = input;
        self
    }
    /// <p>The collaborator's name.</p>
    pub fn get_agent_collaborator_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_collaborator_name
    }
    /// <p>The collaborator's alias ARN.</p>
    pub fn agent_collaborator_alias_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_collaborator_alias_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The collaborator's alias ARN.</p>
    pub fn set_agent_collaborator_alias_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_collaborator_alias_arn = input;
        self
    }
    /// <p>The collaborator's alias ARN.</p>
    pub fn get_agent_collaborator_alias_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_collaborator_alias_arn
    }
    /// <p>Text or action invocation result input for the collaborator.</p>
    pub fn input(mut self, input: crate::types::AgentCollaboratorInputPayload) -> Self {
        self.input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Text or action invocation result input for the collaborator.</p>
    pub fn set_input(mut self, input: ::std::option::Option<crate::types::AgentCollaboratorInputPayload>) -> Self {
        self.input = input;
        self
    }
    /// <p>Text or action invocation result input for the collaborator.</p>
    pub fn get_input(&self) -> &::std::option::Option<crate::types::AgentCollaboratorInputPayload> {
        &self.input
    }
    /// Consumes the builder and constructs a [`AgentCollaboratorInvocationInput`](crate::types::AgentCollaboratorInvocationInput).
    pub fn build(self) -> crate::types::AgentCollaboratorInvocationInput {
        crate::types::AgentCollaboratorInvocationInput {
            agent_collaborator_name: self.agent_collaborator_name,
            agent_collaborator_alias_arn: self.agent_collaborator_alias_arn,
            input: self.input,
        }
    }
}
