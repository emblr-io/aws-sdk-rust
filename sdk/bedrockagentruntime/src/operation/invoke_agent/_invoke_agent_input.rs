// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InvokeAgentInput {
    /// <p>Contains parameters that specify various attributes of the session. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a>.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub session_state: ::std::option::Option<crate::types::SessionState>,
    /// <p>The unique identifier of the agent to use.</p>
    pub agent_id: ::std::option::Option<::std::string::String>,
    /// <p>The alias of the agent to use.</p>
    pub agent_alias_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the session. Use the same value across requests to continue the same conversation.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether to end the session with the agent or not.</p>
    pub end_session: ::std::option::Option<bool>,
    /// <p>Specifies whether to turn on the trace or not to track the agent's reasoning process. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-test.html#trace-events">Trace enablement</a>.</p>
    pub enable_trace: ::std::option::Option<bool>,
    /// <p>The prompt text to send the agent.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub input_text: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the agent memory.</p>
    pub memory_id: ::std::option::Option<::std::string::String>,
    /// <p>Model performance settings for the request.</p>
    pub bedrock_model_configurations: ::std::option::Option<crate::types::BedrockModelConfigurations>,
    /// <p>Specifies the configurations for streaming.</p><note>
    /// <p>To use agent streaming, you need permissions to perform the <code>bedrock:InvokeModelWithResponseStream</code> action.</p>
    /// </note>
    pub streaming_configurations: ::std::option::Option<crate::types::StreamingConfigurations>,
    /// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
    pub prompt_creation_configurations: ::std::option::Option<crate::types::PromptCreationConfigurations>,
    /// <p>The ARN of the resource making the request.</p>
    pub source_arn: ::std::option::Option<::std::string::String>,
}
impl InvokeAgentInput {
    /// <p>Contains parameters that specify various attributes of the session. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a>.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn session_state(&self) -> ::std::option::Option<&crate::types::SessionState> {
        self.session_state.as_ref()
    }
    /// <p>The unique identifier of the agent to use.</p>
    pub fn agent_id(&self) -> ::std::option::Option<&str> {
        self.agent_id.as_deref()
    }
    /// <p>The alias of the agent to use.</p>
    pub fn agent_alias_id(&self) -> ::std::option::Option<&str> {
        self.agent_alias_id.as_deref()
    }
    /// <p>The unique identifier of the session. Use the same value across requests to continue the same conversation.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
    /// <p>Specifies whether to end the session with the agent or not.</p>
    pub fn end_session(&self) -> ::std::option::Option<bool> {
        self.end_session
    }
    /// <p>Specifies whether to turn on the trace or not to track the agent's reasoning process. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-test.html#trace-events">Trace enablement</a>.</p>
    pub fn enable_trace(&self) -> ::std::option::Option<bool> {
        self.enable_trace
    }
    /// <p>The prompt text to send the agent.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn input_text(&self) -> ::std::option::Option<&str> {
        self.input_text.as_deref()
    }
    /// <p>The unique identifier of the agent memory.</p>
    pub fn memory_id(&self) -> ::std::option::Option<&str> {
        self.memory_id.as_deref()
    }
    /// <p>Model performance settings for the request.</p>
    pub fn bedrock_model_configurations(&self) -> ::std::option::Option<&crate::types::BedrockModelConfigurations> {
        self.bedrock_model_configurations.as_ref()
    }
    /// <p>Specifies the configurations for streaming.</p><note>
    /// <p>To use agent streaming, you need permissions to perform the <code>bedrock:InvokeModelWithResponseStream</code> action.</p>
    /// </note>
    pub fn streaming_configurations(&self) -> ::std::option::Option<&crate::types::StreamingConfigurations> {
        self.streaming_configurations.as_ref()
    }
    /// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
    pub fn prompt_creation_configurations(&self) -> ::std::option::Option<&crate::types::PromptCreationConfigurations> {
        self.prompt_creation_configurations.as_ref()
    }
    /// <p>The ARN of the resource making the request.</p>
    pub fn source_arn(&self) -> ::std::option::Option<&str> {
        self.source_arn.as_deref()
    }
}
impl ::std::fmt::Debug for InvokeAgentInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeAgentInput");
        formatter.field("session_state", &self.session_state);
        formatter.field("agent_id", &self.agent_id);
        formatter.field("agent_alias_id", &self.agent_alias_id);
        formatter.field("session_id", &self.session_id);
        formatter.field("end_session", &self.end_session);
        formatter.field("enable_trace", &self.enable_trace);
        formatter.field("input_text", &"*** Sensitive Data Redacted ***");
        formatter.field("memory_id", &self.memory_id);
        formatter.field("bedrock_model_configurations", &self.bedrock_model_configurations);
        formatter.field("streaming_configurations", &self.streaming_configurations);
        formatter.field("prompt_creation_configurations", &self.prompt_creation_configurations);
        formatter.field("source_arn", &self.source_arn);
        formatter.finish()
    }
}
impl InvokeAgentInput {
    /// Creates a new builder-style object to manufacture [`InvokeAgentInput`](crate::operation::invoke_agent::InvokeAgentInput).
    pub fn builder() -> crate::operation::invoke_agent::builders::InvokeAgentInputBuilder {
        crate::operation::invoke_agent::builders::InvokeAgentInputBuilder::default()
    }
}

/// A builder for [`InvokeAgentInput`](crate::operation::invoke_agent::InvokeAgentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InvokeAgentInputBuilder {
    pub(crate) session_state: ::std::option::Option<crate::types::SessionState>,
    pub(crate) agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) agent_alias_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) end_session: ::std::option::Option<bool>,
    pub(crate) enable_trace: ::std::option::Option<bool>,
    pub(crate) input_text: ::std::option::Option<::std::string::String>,
    pub(crate) memory_id: ::std::option::Option<::std::string::String>,
    pub(crate) bedrock_model_configurations: ::std::option::Option<crate::types::BedrockModelConfigurations>,
    pub(crate) streaming_configurations: ::std::option::Option<crate::types::StreamingConfigurations>,
    pub(crate) prompt_creation_configurations: ::std::option::Option<crate::types::PromptCreationConfigurations>,
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
}
impl InvokeAgentInputBuilder {
    /// <p>Contains parameters that specify various attributes of the session. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a>.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn session_state(mut self, input: crate::types::SessionState) -> Self {
        self.session_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains parameters that specify various attributes of the session. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a>.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn set_session_state(mut self, input: ::std::option::Option<crate::types::SessionState>) -> Self {
        self.session_state = input;
        self
    }
    /// <p>Contains parameters that specify various attributes of the session. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a>.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn get_session_state(&self) -> &::std::option::Option<crate::types::SessionState> {
        &self.session_state
    }
    /// <p>The unique identifier of the agent to use.</p>
    /// This field is required.
    pub fn agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agent to use.</p>
    pub fn set_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_id = input;
        self
    }
    /// <p>The unique identifier of the agent to use.</p>
    pub fn get_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_id
    }
    /// <p>The alias of the agent to use.</p>
    /// This field is required.
    pub fn agent_alias_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_alias_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the agent to use.</p>
    pub fn set_agent_alias_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_alias_id = input;
        self
    }
    /// <p>The alias of the agent to use.</p>
    pub fn get_agent_alias_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_alias_id
    }
    /// <p>The unique identifier of the session. Use the same value across requests to continue the same conversation.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the session. Use the same value across requests to continue the same conversation.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier of the session. Use the same value across requests to continue the same conversation.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>Specifies whether to end the session with the agent or not.</p>
    pub fn end_session(mut self, input: bool) -> Self {
        self.end_session = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to end the session with the agent or not.</p>
    pub fn set_end_session(mut self, input: ::std::option::Option<bool>) -> Self {
        self.end_session = input;
        self
    }
    /// <p>Specifies whether to end the session with the agent or not.</p>
    pub fn get_end_session(&self) -> &::std::option::Option<bool> {
        &self.end_session
    }
    /// <p>Specifies whether to turn on the trace or not to track the agent's reasoning process. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-test.html#trace-events">Trace enablement</a>.</p>
    pub fn enable_trace(mut self, input: bool) -> Self {
        self.enable_trace = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to turn on the trace or not to track the agent's reasoning process. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-test.html#trace-events">Trace enablement</a>.</p>
    pub fn set_enable_trace(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_trace = input;
        self
    }
    /// <p>Specifies whether to turn on the trace or not to track the agent's reasoning process. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-test.html#trace-events">Trace enablement</a>.</p>
    pub fn get_enable_trace(&self) -> &::std::option::Option<bool> {
        &self.enable_trace
    }
    /// <p>The prompt text to send the agent.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn input_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prompt text to send the agent.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn set_input_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_text = input;
        self
    }
    /// <p>The prompt text to send the agent.</p><note>
    /// <p>If you include <code>returnControlInvocationResults</code> in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn get_input_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_text
    }
    /// <p>The unique identifier of the agent memory.</p>
    pub fn memory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.memory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agent memory.</p>
    pub fn set_memory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.memory_id = input;
        self
    }
    /// <p>The unique identifier of the agent memory.</p>
    pub fn get_memory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.memory_id
    }
    /// <p>Model performance settings for the request.</p>
    pub fn bedrock_model_configurations(mut self, input: crate::types::BedrockModelConfigurations) -> Self {
        self.bedrock_model_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Model performance settings for the request.</p>
    pub fn set_bedrock_model_configurations(mut self, input: ::std::option::Option<crate::types::BedrockModelConfigurations>) -> Self {
        self.bedrock_model_configurations = input;
        self
    }
    /// <p>Model performance settings for the request.</p>
    pub fn get_bedrock_model_configurations(&self) -> &::std::option::Option<crate::types::BedrockModelConfigurations> {
        &self.bedrock_model_configurations
    }
    /// <p>Specifies the configurations for streaming.</p><note>
    /// <p>To use agent streaming, you need permissions to perform the <code>bedrock:InvokeModelWithResponseStream</code> action.</p>
    /// </note>
    pub fn streaming_configurations(mut self, input: crate::types::StreamingConfigurations) -> Self {
        self.streaming_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configurations for streaming.</p><note>
    /// <p>To use agent streaming, you need permissions to perform the <code>bedrock:InvokeModelWithResponseStream</code> action.</p>
    /// </note>
    pub fn set_streaming_configurations(mut self, input: ::std::option::Option<crate::types::StreamingConfigurations>) -> Self {
        self.streaming_configurations = input;
        self
    }
    /// <p>Specifies the configurations for streaming.</p><note>
    /// <p>To use agent streaming, you need permissions to perform the <code>bedrock:InvokeModelWithResponseStream</code> action.</p>
    /// </note>
    pub fn get_streaming_configurations(&self) -> &::std::option::Option<crate::types::StreamingConfigurations> {
        &self.streaming_configurations
    }
    /// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
    pub fn prompt_creation_configurations(mut self, input: crate::types::PromptCreationConfigurations) -> Self {
        self.prompt_creation_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
    pub fn set_prompt_creation_configurations(mut self, input: ::std::option::Option<crate::types::PromptCreationConfigurations>) -> Self {
        self.prompt_creation_configurations = input;
        self
    }
    /// <p>Specifies parameters that control how the service populates the agent prompt for an <code>InvokeAgent</code> request. You can control which aspects of previous invocations in the same agent session the service uses to populate the agent prompt. This gives you more granular control over the contextual history that is used to process the current request.</p>
    pub fn get_prompt_creation_configurations(&self) -> &::std::option::Option<crate::types::PromptCreationConfigurations> {
        &self.prompt_creation_configurations
    }
    /// <p>The ARN of the resource making the request.</p>
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the resource making the request.</p>
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// <p>The ARN of the resource making the request.</p>
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// Consumes the builder and constructs a [`InvokeAgentInput`](crate::operation::invoke_agent::InvokeAgentInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::invoke_agent::InvokeAgentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::invoke_agent::InvokeAgentInput {
            session_state: self.session_state,
            agent_id: self.agent_id,
            agent_alias_id: self.agent_alias_id,
            session_id: self.session_id,
            end_session: self.end_session,
            enable_trace: self.enable_trace,
            input_text: self.input_text,
            memory_id: self.memory_id,
            bedrock_model_configurations: self.bedrock_model_configurations,
            streaming_configurations: self.streaming_configurations,
            prompt_creation_configurations: self.prompt_creation_configurations,
            source_arn: self.source_arn,
        })
    }
}
impl ::std::fmt::Debug for InvokeAgentInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeAgentInputBuilder");
        formatter.field("session_state", &self.session_state);
        formatter.field("agent_id", &self.agent_id);
        formatter.field("agent_alias_id", &self.agent_alias_id);
        formatter.field("session_id", &self.session_id);
        formatter.field("end_session", &self.end_session);
        formatter.field("enable_trace", &self.enable_trace);
        formatter.field("input_text", &"*** Sensitive Data Redacted ***");
        formatter.field("memory_id", &self.memory_id);
        formatter.field("bedrock_model_configurations", &self.bedrock_model_configurations);
        formatter.field("streaming_configurations", &self.streaming_configurations);
        formatter.field("prompt_creation_configurations", &self.prompt_creation_configurations);
        formatter.field("source_arn", &self.source_arn);
        formatter.finish()
    }
}
