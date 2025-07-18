// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> or <code>InvokeInlineAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PromptCreationConfigurations {
    /// <p>The number of previous conversations from the ongoing agent session to include in the conversation history of the agent prompt, during the current invocation. This gives you more granular control over the context that the model is made aware of, and helps the model remove older context which is no longer useful during the ongoing agent session.</p>
    pub previous_conversation_turns_to_include: ::std::option::Option<i32>,
    /// <p>If <code>true</code>, the service removes any content between <code>&lt;thinking&gt;</code> tags from previous conversations in an agent session. The service will only remove content from already processed turns. This helps you remove content which might not be useful for current and subsequent invocations. This can reduce the input token count and potentially save costs. The default value is <code>false</code>.</p>
    pub exclude_previous_thinking_steps: bool,
}
impl PromptCreationConfigurations {
    /// <p>The number of previous conversations from the ongoing agent session to include in the conversation history of the agent prompt, during the current invocation. This gives you more granular control over the context that the model is made aware of, and helps the model remove older context which is no longer useful during the ongoing agent session.</p>
    pub fn previous_conversation_turns_to_include(&self) -> ::std::option::Option<i32> {
        self.previous_conversation_turns_to_include
    }
    /// <p>If <code>true</code>, the service removes any content between <code>&lt;thinking&gt;</code> tags from previous conversations in an agent session. The service will only remove content from already processed turns. This helps you remove content which might not be useful for current and subsequent invocations. This can reduce the input token count and potentially save costs. The default value is <code>false</code>.</p>
    pub fn exclude_previous_thinking_steps(&self) -> bool {
        self.exclude_previous_thinking_steps
    }
}
impl PromptCreationConfigurations {
    /// Creates a new builder-style object to manufacture [`PromptCreationConfigurations`](crate::types::PromptCreationConfigurations).
    pub fn builder() -> crate::types::builders::PromptCreationConfigurationsBuilder {
        crate::types::builders::PromptCreationConfigurationsBuilder::default()
    }
}

/// A builder for [`PromptCreationConfigurations`](crate::types::PromptCreationConfigurations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PromptCreationConfigurationsBuilder {
    pub(crate) previous_conversation_turns_to_include: ::std::option::Option<i32>,
    pub(crate) exclude_previous_thinking_steps: ::std::option::Option<bool>,
}
impl PromptCreationConfigurationsBuilder {
    /// <p>The number of previous conversations from the ongoing agent session to include in the conversation history of the agent prompt, during the current invocation. This gives you more granular control over the context that the model is made aware of, and helps the model remove older context which is no longer useful during the ongoing agent session.</p>
    pub fn previous_conversation_turns_to_include(mut self, input: i32) -> Self {
        self.previous_conversation_turns_to_include = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of previous conversations from the ongoing agent session to include in the conversation history of the agent prompt, during the current invocation. This gives you more granular control over the context that the model is made aware of, and helps the model remove older context which is no longer useful during the ongoing agent session.</p>
    pub fn set_previous_conversation_turns_to_include(mut self, input: ::std::option::Option<i32>) -> Self {
        self.previous_conversation_turns_to_include = input;
        self
    }
    /// <p>The number of previous conversations from the ongoing agent session to include in the conversation history of the agent prompt, during the current invocation. This gives you more granular control over the context that the model is made aware of, and helps the model remove older context which is no longer useful during the ongoing agent session.</p>
    pub fn get_previous_conversation_turns_to_include(&self) -> &::std::option::Option<i32> {
        &self.previous_conversation_turns_to_include
    }
    /// <p>If <code>true</code>, the service removes any content between <code>&lt;thinking&gt;</code> tags from previous conversations in an agent session. The service will only remove content from already processed turns. This helps you remove content which might not be useful for current and subsequent invocations. This can reduce the input token count and potentially save costs. The default value is <code>false</code>.</p>
    pub fn exclude_previous_thinking_steps(mut self, input: bool) -> Self {
        self.exclude_previous_thinking_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>true</code>, the service removes any content between <code>&lt;thinking&gt;</code> tags from previous conversations in an agent session. The service will only remove content from already processed turns. This helps you remove content which might not be useful for current and subsequent invocations. This can reduce the input token count and potentially save costs. The default value is <code>false</code>.</p>
    pub fn set_exclude_previous_thinking_steps(mut self, input: ::std::option::Option<bool>) -> Self {
        self.exclude_previous_thinking_steps = input;
        self
    }
    /// <p>If <code>true</code>, the service removes any content between <code>&lt;thinking&gt;</code> tags from previous conversations in an agent session. The service will only remove content from already processed turns. This helps you remove content which might not be useful for current and subsequent invocations. This can reduce the input token count and potentially save costs. The default value is <code>false</code>.</p>
    pub fn get_exclude_previous_thinking_steps(&self) -> &::std::option::Option<bool> {
        &self.exclude_previous_thinking_steps
    }
    /// Consumes the builder and constructs a [`PromptCreationConfigurations`](crate::types::PromptCreationConfigurations).
    pub fn build(self) -> crate::types::PromptCreationConfigurations {
        crate::types::PromptCreationConfigurations {
            previous_conversation_turns_to_include: self.previous_conversation_turns_to_include,
            exclude_previous_thinking_steps: self.exclude_previous_thinking_steps.unwrap_or_default(),
        }
    }
}
