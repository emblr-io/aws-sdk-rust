// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for AI Agents of type SELF_SERVICE.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SelfServiceAiAgentConfiguration {
    /// <p>The AI Prompt identifier for the Self Service Pre-Processing prompt used by the SELF_SERVICE AI Agent</p>
    pub self_service_pre_processing_ai_prompt_id: ::std::option::Option<::std::string::String>,
    /// <p>The AI Prompt identifier for the Self Service Answer Generation prompt used by the SELF_SERVICE AI Agent</p>
    pub self_service_answer_generation_ai_prompt_id: ::std::option::Option<::std::string::String>,
    /// <p>The AI Guardrail identifier used by the SELF_SERVICE AI Agent.</p>
    pub self_service_ai_guardrail_id: ::std::option::Option<::std::string::String>,
    /// <p>The association configurations for overriding behavior on this AI Agent.</p>
    pub association_configurations: ::std::option::Option<::std::vec::Vec<crate::types::AssociationConfiguration>>,
}
impl SelfServiceAiAgentConfiguration {
    /// <p>The AI Prompt identifier for the Self Service Pre-Processing prompt used by the SELF_SERVICE AI Agent</p>
    pub fn self_service_pre_processing_ai_prompt_id(&self) -> ::std::option::Option<&str> {
        self.self_service_pre_processing_ai_prompt_id.as_deref()
    }
    /// <p>The AI Prompt identifier for the Self Service Answer Generation prompt used by the SELF_SERVICE AI Agent</p>
    pub fn self_service_answer_generation_ai_prompt_id(&self) -> ::std::option::Option<&str> {
        self.self_service_answer_generation_ai_prompt_id.as_deref()
    }
    /// <p>The AI Guardrail identifier used by the SELF_SERVICE AI Agent.</p>
    pub fn self_service_ai_guardrail_id(&self) -> ::std::option::Option<&str> {
        self.self_service_ai_guardrail_id.as_deref()
    }
    /// <p>The association configurations for overriding behavior on this AI Agent.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.association_configurations.is_none()`.
    pub fn association_configurations(&self) -> &[crate::types::AssociationConfiguration] {
        self.association_configurations.as_deref().unwrap_or_default()
    }
}
impl SelfServiceAiAgentConfiguration {
    /// Creates a new builder-style object to manufacture [`SelfServiceAiAgentConfiguration`](crate::types::SelfServiceAiAgentConfiguration).
    pub fn builder() -> crate::types::builders::SelfServiceAiAgentConfigurationBuilder {
        crate::types::builders::SelfServiceAiAgentConfigurationBuilder::default()
    }
}

/// A builder for [`SelfServiceAiAgentConfiguration`](crate::types::SelfServiceAiAgentConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SelfServiceAiAgentConfigurationBuilder {
    pub(crate) self_service_pre_processing_ai_prompt_id: ::std::option::Option<::std::string::String>,
    pub(crate) self_service_answer_generation_ai_prompt_id: ::std::option::Option<::std::string::String>,
    pub(crate) self_service_ai_guardrail_id: ::std::option::Option<::std::string::String>,
    pub(crate) association_configurations: ::std::option::Option<::std::vec::Vec<crate::types::AssociationConfiguration>>,
}
impl SelfServiceAiAgentConfigurationBuilder {
    /// <p>The AI Prompt identifier for the Self Service Pre-Processing prompt used by the SELF_SERVICE AI Agent</p>
    pub fn self_service_pre_processing_ai_prompt_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.self_service_pre_processing_ai_prompt_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AI Prompt identifier for the Self Service Pre-Processing prompt used by the SELF_SERVICE AI Agent</p>
    pub fn set_self_service_pre_processing_ai_prompt_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.self_service_pre_processing_ai_prompt_id = input;
        self
    }
    /// <p>The AI Prompt identifier for the Self Service Pre-Processing prompt used by the SELF_SERVICE AI Agent</p>
    pub fn get_self_service_pre_processing_ai_prompt_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.self_service_pre_processing_ai_prompt_id
    }
    /// <p>The AI Prompt identifier for the Self Service Answer Generation prompt used by the SELF_SERVICE AI Agent</p>
    pub fn self_service_answer_generation_ai_prompt_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.self_service_answer_generation_ai_prompt_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AI Prompt identifier for the Self Service Answer Generation prompt used by the SELF_SERVICE AI Agent</p>
    pub fn set_self_service_answer_generation_ai_prompt_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.self_service_answer_generation_ai_prompt_id = input;
        self
    }
    /// <p>The AI Prompt identifier for the Self Service Answer Generation prompt used by the SELF_SERVICE AI Agent</p>
    pub fn get_self_service_answer_generation_ai_prompt_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.self_service_answer_generation_ai_prompt_id
    }
    /// <p>The AI Guardrail identifier used by the SELF_SERVICE AI Agent.</p>
    pub fn self_service_ai_guardrail_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.self_service_ai_guardrail_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AI Guardrail identifier used by the SELF_SERVICE AI Agent.</p>
    pub fn set_self_service_ai_guardrail_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.self_service_ai_guardrail_id = input;
        self
    }
    /// <p>The AI Guardrail identifier used by the SELF_SERVICE AI Agent.</p>
    pub fn get_self_service_ai_guardrail_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.self_service_ai_guardrail_id
    }
    /// Appends an item to `association_configurations`.
    ///
    /// To override the contents of this collection use [`set_association_configurations`](Self::set_association_configurations).
    ///
    /// <p>The association configurations for overriding behavior on this AI Agent.</p>
    pub fn association_configurations(mut self, input: crate::types::AssociationConfiguration) -> Self {
        let mut v = self.association_configurations.unwrap_or_default();
        v.push(input);
        self.association_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The association configurations for overriding behavior on this AI Agent.</p>
    pub fn set_association_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AssociationConfiguration>>) -> Self {
        self.association_configurations = input;
        self
    }
    /// <p>The association configurations for overriding behavior on this AI Agent.</p>
    pub fn get_association_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssociationConfiguration>> {
        &self.association_configurations
    }
    /// Consumes the builder and constructs a [`SelfServiceAiAgentConfiguration`](crate::types::SelfServiceAiAgentConfiguration).
    pub fn build(self) -> crate::types::SelfServiceAiAgentConfiguration {
        crate::types::SelfServiceAiAgentConfiguration {
            self_service_pre_processing_ai_prompt_id: self.self_service_pre_processing_ai_prompt_id,
            self_service_answer_generation_ai_prompt_id: self.self_service_answer_generation_ai_prompt_id,
            self_service_ai_guardrail_id: self.self_service_ai_guardrail_id,
            association_configurations: self.association_configurations,
        }
    }
}
