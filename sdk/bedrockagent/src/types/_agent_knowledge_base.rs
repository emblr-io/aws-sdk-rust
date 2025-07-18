// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about a knowledge base that is associated with an agent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AgentKnowledgeBase {
    /// <p>The unique identifier of the agent with which the knowledge base is associated.</p>
    pub agent_id: ::std::string::String,
    /// <p>The version of the agent with which the knowledge base is associated.</p>
    pub agent_version: ::std::string::String,
    /// <p>The unique identifier of the association between the agent and the knowledge base.</p>
    pub knowledge_base_id: ::std::string::String,
    /// <p>The description of the association between the agent and the knowledge base.</p>
    pub description: ::std::string::String,
    /// <p>The time at which the association between the agent and the knowledge base was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The time at which the association between the agent and the knowledge base was last updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>Specifies whether to use the knowledge base or not when sending an <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html">InvokeAgent</a> request.</p>
    pub knowledge_base_state: crate::types::KnowledgeBaseState,
}
impl AgentKnowledgeBase {
    /// <p>The unique identifier of the agent with which the knowledge base is associated.</p>
    pub fn agent_id(&self) -> &str {
        use std::ops::Deref;
        self.agent_id.deref()
    }
    /// <p>The version of the agent with which the knowledge base is associated.</p>
    pub fn agent_version(&self) -> &str {
        use std::ops::Deref;
        self.agent_version.deref()
    }
    /// <p>The unique identifier of the association between the agent and the knowledge base.</p>
    pub fn knowledge_base_id(&self) -> &str {
        use std::ops::Deref;
        self.knowledge_base_id.deref()
    }
    /// <p>The description of the association between the agent and the knowledge base.</p>
    pub fn description(&self) -> &str {
        use std::ops::Deref;
        self.description.deref()
    }
    /// <p>The time at which the association between the agent and the knowledge base was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The time at which the association between the agent and the knowledge base was last updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>Specifies whether to use the knowledge base or not when sending an <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html">InvokeAgent</a> request.</p>
    pub fn knowledge_base_state(&self) -> &crate::types::KnowledgeBaseState {
        &self.knowledge_base_state
    }
}
impl AgentKnowledgeBase {
    /// Creates a new builder-style object to manufacture [`AgentKnowledgeBase`](crate::types::AgentKnowledgeBase).
    pub fn builder() -> crate::types::builders::AgentKnowledgeBaseBuilder {
        crate::types::builders::AgentKnowledgeBaseBuilder::default()
    }
}

/// A builder for [`AgentKnowledgeBase`](crate::types::AgentKnowledgeBase).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AgentKnowledgeBaseBuilder {
    pub(crate) agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) agent_version: ::std::option::Option<::std::string::String>,
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) knowledge_base_state: ::std::option::Option<crate::types::KnowledgeBaseState>,
}
impl AgentKnowledgeBaseBuilder {
    /// <p>The unique identifier of the agent with which the knowledge base is associated.</p>
    /// This field is required.
    pub fn agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agent with which the knowledge base is associated.</p>
    pub fn set_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_id = input;
        self
    }
    /// <p>The unique identifier of the agent with which the knowledge base is associated.</p>
    pub fn get_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_id
    }
    /// <p>The version of the agent with which the knowledge base is associated.</p>
    /// This field is required.
    pub fn agent_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the agent with which the knowledge base is associated.</p>
    pub fn set_agent_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_version = input;
        self
    }
    /// <p>The version of the agent with which the knowledge base is associated.</p>
    pub fn get_agent_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_version
    }
    /// <p>The unique identifier of the association between the agent and the knowledge base.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the association between the agent and the knowledge base.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The unique identifier of the association between the agent and the knowledge base.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The description of the association between the agent and the knowledge base.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the association between the agent and the knowledge base.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the association between the agent and the knowledge base.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The time at which the association between the agent and the knowledge base was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the association between the agent and the knowledge base was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time at which the association between the agent and the knowledge base was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The time at which the association between the agent and the knowledge base was last updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the association between the agent and the knowledge base was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The time at which the association between the agent and the knowledge base was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>Specifies whether to use the knowledge base or not when sending an <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html">InvokeAgent</a> request.</p>
    /// This field is required.
    pub fn knowledge_base_state(mut self, input: crate::types::KnowledgeBaseState) -> Self {
        self.knowledge_base_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to use the knowledge base or not when sending an <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html">InvokeAgent</a> request.</p>
    pub fn set_knowledge_base_state(mut self, input: ::std::option::Option<crate::types::KnowledgeBaseState>) -> Self {
        self.knowledge_base_state = input;
        self
    }
    /// <p>Specifies whether to use the knowledge base or not when sending an <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html">InvokeAgent</a> request.</p>
    pub fn get_knowledge_base_state(&self) -> &::std::option::Option<crate::types::KnowledgeBaseState> {
        &self.knowledge_base_state
    }
    /// Consumes the builder and constructs a [`AgentKnowledgeBase`](crate::types::AgentKnowledgeBase).
    /// This method will fail if any of the following fields are not set:
    /// - [`agent_id`](crate::types::builders::AgentKnowledgeBaseBuilder::agent_id)
    /// - [`agent_version`](crate::types::builders::AgentKnowledgeBaseBuilder::agent_version)
    /// - [`knowledge_base_id`](crate::types::builders::AgentKnowledgeBaseBuilder::knowledge_base_id)
    /// - [`description`](crate::types::builders::AgentKnowledgeBaseBuilder::description)
    /// - [`created_at`](crate::types::builders::AgentKnowledgeBaseBuilder::created_at)
    /// - [`updated_at`](crate::types::builders::AgentKnowledgeBaseBuilder::updated_at)
    /// - [`knowledge_base_state`](crate::types::builders::AgentKnowledgeBaseBuilder::knowledge_base_state)
    pub fn build(self) -> ::std::result::Result<crate::types::AgentKnowledgeBase, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AgentKnowledgeBase {
            agent_id: self.agent_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "agent_id",
                    "agent_id was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            agent_version: self.agent_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "agent_version",
                    "agent_version was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            knowledge_base_id: self.knowledge_base_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "knowledge_base_id",
                    "knowledge_base_id was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            description: self.description.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "description",
                    "description was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
            knowledge_base_state: self.knowledge_base_state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "knowledge_base_state",
                    "knowledge_base_state was not specified but it is required when building AgentKnowledgeBase",
                )
            })?,
        })
    }
}
