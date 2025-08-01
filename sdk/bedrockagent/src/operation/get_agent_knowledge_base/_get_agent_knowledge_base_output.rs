// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAgentKnowledgeBaseOutput {
    /// <p>Contains details about a knowledge base attached to an agent.</p>
    pub agent_knowledge_base: ::std::option::Option<crate::types::AgentKnowledgeBase>,
    _request_id: Option<String>,
}
impl GetAgentKnowledgeBaseOutput {
    /// <p>Contains details about a knowledge base attached to an agent.</p>
    pub fn agent_knowledge_base(&self) -> ::std::option::Option<&crate::types::AgentKnowledgeBase> {
        self.agent_knowledge_base.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAgentKnowledgeBaseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAgentKnowledgeBaseOutput {
    /// Creates a new builder-style object to manufacture [`GetAgentKnowledgeBaseOutput`](crate::operation::get_agent_knowledge_base::GetAgentKnowledgeBaseOutput).
    pub fn builder() -> crate::operation::get_agent_knowledge_base::builders::GetAgentKnowledgeBaseOutputBuilder {
        crate::operation::get_agent_knowledge_base::builders::GetAgentKnowledgeBaseOutputBuilder::default()
    }
}

/// A builder for [`GetAgentKnowledgeBaseOutput`](crate::operation::get_agent_knowledge_base::GetAgentKnowledgeBaseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAgentKnowledgeBaseOutputBuilder {
    pub(crate) agent_knowledge_base: ::std::option::Option<crate::types::AgentKnowledgeBase>,
    _request_id: Option<String>,
}
impl GetAgentKnowledgeBaseOutputBuilder {
    /// <p>Contains details about a knowledge base attached to an agent.</p>
    /// This field is required.
    pub fn agent_knowledge_base(mut self, input: crate::types::AgentKnowledgeBase) -> Self {
        self.agent_knowledge_base = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about a knowledge base attached to an agent.</p>
    pub fn set_agent_knowledge_base(mut self, input: ::std::option::Option<crate::types::AgentKnowledgeBase>) -> Self {
        self.agent_knowledge_base = input;
        self
    }
    /// <p>Contains details about a knowledge base attached to an agent.</p>
    pub fn get_agent_knowledge_base(&self) -> &::std::option::Option<crate::types::AgentKnowledgeBase> {
        &self.agent_knowledge_base
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAgentKnowledgeBaseOutput`](crate::operation::get_agent_knowledge_base::GetAgentKnowledgeBaseOutput).
    pub fn build(self) -> crate::operation::get_agent_knowledge_base::GetAgentKnowledgeBaseOutput {
        crate::operation::get_agent_knowledge_base::GetAgentKnowledgeBaseOutput {
            agent_knowledge_base: self.agent_knowledge_base,
            _request_id: self._request_id,
        }
    }
}
