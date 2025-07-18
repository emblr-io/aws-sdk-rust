// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains parameters that specify various attributes that persist across a session or prompt. You can define session state attributes as key-value pairs when writing a <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-lambda.html">Lambda function</a> for an action group or pass them when making an <code>InvokeInlineAgent</code> request. Use session state attributes to control and provide conversational context for your inline agent and to help customize your agent's behavior. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-session-state.html">Control session context</a></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InlineSessionState {
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub session_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub prompt_session_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Contains information about the results from the action group invocation. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p><note>
    /// <p>If you include this field in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub return_control_invocation_results: ::std::option::Option<::std::vec::Vec<crate::types::InvocationResultMember>>,
    /// <p>The identifier of the invocation of an action. This value must match the <code>invocationId</code> returned in the <code>InvokeInlineAgent</code> response for the action whose results are provided in the <code>returnControlInvocationResults</code> field. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p>
    pub invocation_id: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the files used by code interpreter.</p>
    pub files: ::std::option::Option<::std::vec::Vec<crate::types::InputFile>>,
    /// <p>Contains the conversation history that persist across sessions.</p>
    pub conversation_history: ::std::option::Option<crate::types::ConversationHistory>,
}
impl InlineSessionState {
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn session_attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.session_attributes.as_ref()
    }
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn prompt_session_attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.prompt_session_attributes.as_ref()
    }
    /// <p>Contains information about the results from the action group invocation. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p><note>
    /// <p>If you include this field in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.return_control_invocation_results.is_none()`.
    pub fn return_control_invocation_results(&self) -> &[crate::types::InvocationResultMember] {
        self.return_control_invocation_results.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of the invocation of an action. This value must match the <code>invocationId</code> returned in the <code>InvokeInlineAgent</code> response for the action whose results are provided in the <code>returnControlInvocationResults</code> field. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p>
    pub fn invocation_id(&self) -> ::std::option::Option<&str> {
        self.invocation_id.as_deref()
    }
    /// <p>Contains information about the files used by code interpreter.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.files.is_none()`.
    pub fn files(&self) -> &[crate::types::InputFile] {
        self.files.as_deref().unwrap_or_default()
    }
    /// <p>Contains the conversation history that persist across sessions.</p>
    pub fn conversation_history(&self) -> ::std::option::Option<&crate::types::ConversationHistory> {
        self.conversation_history.as_ref()
    }
}
impl InlineSessionState {
    /// Creates a new builder-style object to manufacture [`InlineSessionState`](crate::types::InlineSessionState).
    pub fn builder() -> crate::types::builders::InlineSessionStateBuilder {
        crate::types::builders::InlineSessionStateBuilder::default()
    }
}

/// A builder for [`InlineSessionState`](crate::types::InlineSessionState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InlineSessionStateBuilder {
    pub(crate) session_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) prompt_session_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) return_control_invocation_results: ::std::option::Option<::std::vec::Vec<crate::types::InvocationResultMember>>,
    pub(crate) invocation_id: ::std::option::Option<::std::string::String>,
    pub(crate) files: ::std::option::Option<::std::vec::Vec<crate::types::InputFile>>,
    pub(crate) conversation_history: ::std::option::Option<crate::types::ConversationHistory>,
}
impl InlineSessionStateBuilder {
    /// Adds a key-value pair to `session_attributes`.
    ///
    /// To override the contents of this collection use [`set_session_attributes`](Self::set_session_attributes).
    ///
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn session_attributes(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.session_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.session_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn set_session_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.session_attributes = input;
        self
    }
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn get_session_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.session_attributes
    }
    /// Adds a key-value pair to `prompt_session_attributes`.
    ///
    /// To override the contents of this collection use [`set_prompt_session_attributes`](Self::set_prompt_session_attributes).
    ///
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn prompt_session_attributes(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.prompt_session_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.prompt_session_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn set_prompt_session_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.prompt_session_attributes = input;
        self
    }
    /// <p>Contains attributes that persist across a session and the values of those attributes.</p>
    pub fn get_prompt_session_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.prompt_session_attributes
    }
    /// Appends an item to `return_control_invocation_results`.
    ///
    /// To override the contents of this collection use [`set_return_control_invocation_results`](Self::set_return_control_invocation_results).
    ///
    /// <p>Contains information about the results from the action group invocation. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p><note>
    /// <p>If you include this field in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn return_control_invocation_results(mut self, input: crate::types::InvocationResultMember) -> Self {
        let mut v = self.return_control_invocation_results.unwrap_or_default();
        v.push(input);
        self.return_control_invocation_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information about the results from the action group invocation. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p><note>
    /// <p>If you include this field in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn set_return_control_invocation_results(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::InvocationResultMember>>,
    ) -> Self {
        self.return_control_invocation_results = input;
        self
    }
    /// <p>Contains information about the results from the action group invocation. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p><note>
    /// <p>If you include this field in the <code>sessionState</code> field, the <code>inputText</code> field will be ignored.</p>
    /// </note>
    pub fn get_return_control_invocation_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InvocationResultMember>> {
        &self.return_control_invocation_results
    }
    /// <p>The identifier of the invocation of an action. This value must match the <code>invocationId</code> returned in the <code>InvokeInlineAgent</code> response for the action whose results are provided in the <code>returnControlInvocationResults</code> field. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p>
    pub fn invocation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invocation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the invocation of an action. This value must match the <code>invocationId</code> returned in the <code>InvokeInlineAgent</code> response for the action whose results are provided in the <code>returnControlInvocationResults</code> field. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p>
    pub fn set_invocation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invocation_id = input;
        self
    }
    /// <p>The identifier of the invocation of an action. This value must match the <code>invocationId</code> returned in the <code>InvokeInlineAgent</code> response for the action whose results are provided in the <code>returnControlInvocationResults</code> field. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html">Return control to the agent developer</a>.</p>
    pub fn get_invocation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invocation_id
    }
    /// Appends an item to `files`.
    ///
    /// To override the contents of this collection use [`set_files`](Self::set_files).
    ///
    /// <p>Contains information about the files used by code interpreter.</p>
    pub fn files(mut self, input: crate::types::InputFile) -> Self {
        let mut v = self.files.unwrap_or_default();
        v.push(input);
        self.files = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information about the files used by code interpreter.</p>
    pub fn set_files(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InputFile>>) -> Self {
        self.files = input;
        self
    }
    /// <p>Contains information about the files used by code interpreter.</p>
    pub fn get_files(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InputFile>> {
        &self.files
    }
    /// <p>Contains the conversation history that persist across sessions.</p>
    pub fn conversation_history(mut self, input: crate::types::ConversationHistory) -> Self {
        self.conversation_history = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the conversation history that persist across sessions.</p>
    pub fn set_conversation_history(mut self, input: ::std::option::Option<crate::types::ConversationHistory>) -> Self {
        self.conversation_history = input;
        self
    }
    /// <p>Contains the conversation history that persist across sessions.</p>
    pub fn get_conversation_history(&self) -> &::std::option::Option<crate::types::ConversationHistory> {
        &self.conversation_history
    }
    /// Consumes the builder and constructs a [`InlineSessionState`](crate::types::InlineSessionState).
    pub fn build(self) -> crate::types::InlineSessionState {
        crate::types::InlineSessionState {
            session_attributes: self.session_attributes,
            prompt_session_attributes: self.prompt_session_attributes,
            return_control_invocation_results: self.return_control_invocation_results,
            invocation_id: self.invocation_id,
            files: self.files,
            conversation_history: self.conversation_history,
        }
    }
}
