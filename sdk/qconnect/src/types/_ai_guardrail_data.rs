// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The data for the AI Guardrail</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AiGuardrailData {
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub assistant_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub assistant_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the AI Guardrail.</p>
    pub ai_guardrail_arn: ::std::string::String,
    /// <p>The identifier of the Amazon Q in Connect AI Guardrail.</p>
    pub ai_guardrail_id: ::std::string::String,
    /// <p>The name of the AI Guardrail.</p>
    pub name: ::std::string::String,
    /// <p>The visibility status of the AI Guardrail.</p>
    pub visibility_status: crate::types::VisibilityStatus,
    /// <p>The message to return when the AI Guardrail blocks a prompt.</p>
    pub blocked_input_messaging: ::std::string::String,
    /// <p>The message to return when the AI Guardrail blocks a model response.</p>
    pub blocked_outputs_messaging: ::std::string::String,
    /// <p>A description of the AI Guardrail.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Contains details about topics that the AI Guardrail should identify and deny.</p>
    pub topic_policy_config: ::std::option::Option<crate::types::AiGuardrailTopicPolicyConfig>,
    /// <p>Contains details about how to handle harmful content.</p>
    pub content_policy_config: ::std::option::Option<crate::types::AiGuardrailContentPolicyConfig>,
    /// <p>Contains details about the word policy to configured for the AI Guardrail.</p>
    pub word_policy_config: ::std::option::Option<crate::types::AiGuardrailWordPolicyConfig>,
    /// <p>Contains details about PII entities and regular expressions to configure for the AI Guardrail.</p>
    pub sensitive_information_policy_config: ::std::option::Option<crate::types::AiGuardrailSensitiveInformationPolicyConfig>,
    /// <p>The policy configuration details for the AI Guardrail's contextual grounding policy.</p>
    pub contextual_grounding_policy_config: ::std::option::Option<crate::types::AiGuardrailContextualGroundingPolicyConfig>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The status of the AI Guardrail.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>The time the AI Guardrail was last modified.</p>
    pub modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AiGuardrailData {
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn assistant_id(&self) -> &str {
        use std::ops::Deref;
        self.assistant_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub fn assistant_arn(&self) -> &str {
        use std::ops::Deref;
        self.assistant_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the AI Guardrail.</p>
    pub fn ai_guardrail_arn(&self) -> &str {
        use std::ops::Deref;
        self.ai_guardrail_arn.deref()
    }
    /// <p>The identifier of the Amazon Q in Connect AI Guardrail.</p>
    pub fn ai_guardrail_id(&self) -> &str {
        use std::ops::Deref;
        self.ai_guardrail_id.deref()
    }
    /// <p>The name of the AI Guardrail.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The visibility status of the AI Guardrail.</p>
    pub fn visibility_status(&self) -> &crate::types::VisibilityStatus {
        &self.visibility_status
    }
    /// <p>The message to return when the AI Guardrail blocks a prompt.</p>
    pub fn blocked_input_messaging(&self) -> &str {
        use std::ops::Deref;
        self.blocked_input_messaging.deref()
    }
    /// <p>The message to return when the AI Guardrail blocks a model response.</p>
    pub fn blocked_outputs_messaging(&self) -> &str {
        use std::ops::Deref;
        self.blocked_outputs_messaging.deref()
    }
    /// <p>A description of the AI Guardrail.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Contains details about topics that the AI Guardrail should identify and deny.</p>
    pub fn topic_policy_config(&self) -> ::std::option::Option<&crate::types::AiGuardrailTopicPolicyConfig> {
        self.topic_policy_config.as_ref()
    }
    /// <p>Contains details about how to handle harmful content.</p>
    pub fn content_policy_config(&self) -> ::std::option::Option<&crate::types::AiGuardrailContentPolicyConfig> {
        self.content_policy_config.as_ref()
    }
    /// <p>Contains details about the word policy to configured for the AI Guardrail.</p>
    pub fn word_policy_config(&self) -> ::std::option::Option<&crate::types::AiGuardrailWordPolicyConfig> {
        self.word_policy_config.as_ref()
    }
    /// <p>Contains details about PII entities and regular expressions to configure for the AI Guardrail.</p>
    pub fn sensitive_information_policy_config(&self) -> ::std::option::Option<&crate::types::AiGuardrailSensitiveInformationPolicyConfig> {
        self.sensitive_information_policy_config.as_ref()
    }
    /// <p>The policy configuration details for the AI Guardrail's contextual grounding policy.</p>
    pub fn contextual_grounding_policy_config(&self) -> ::std::option::Option<&crate::types::AiGuardrailContextualGroundingPolicyConfig> {
        self.contextual_grounding_policy_config.as_ref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The status of the AI Guardrail.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>The time the AI Guardrail was last modified.</p>
    pub fn modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_time.as_ref()
    }
}
impl ::std::fmt::Debug for AiGuardrailData {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AiGuardrailData");
        formatter.field("assistant_id", &self.assistant_id);
        formatter.field("assistant_arn", &self.assistant_arn);
        formatter.field("ai_guardrail_arn", &self.ai_guardrail_arn);
        formatter.field("ai_guardrail_id", &self.ai_guardrail_id);
        formatter.field("name", &self.name);
        formatter.field("visibility_status", &self.visibility_status);
        formatter.field("blocked_input_messaging", &"*** Sensitive Data Redacted ***");
        formatter.field("blocked_outputs_messaging", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("topic_policy_config", &self.topic_policy_config);
        formatter.field("content_policy_config", &self.content_policy_config);
        formatter.field("word_policy_config", &self.word_policy_config);
        formatter.field("sensitive_information_policy_config", &self.sensitive_information_policy_config);
        formatter.field("contextual_grounding_policy_config", &self.contextual_grounding_policy_config);
        formatter.field("tags", &self.tags);
        formatter.field("status", &self.status);
        formatter.field("modified_time", &self.modified_time);
        formatter.finish()
    }
}
impl AiGuardrailData {
    /// Creates a new builder-style object to manufacture [`AiGuardrailData`](crate::types::AiGuardrailData).
    pub fn builder() -> crate::types::builders::AiGuardrailDataBuilder {
        crate::types::builders::AiGuardrailDataBuilder::default()
    }
}

/// A builder for [`AiGuardrailData`](crate::types::AiGuardrailData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AiGuardrailDataBuilder {
    pub(crate) assistant_id: ::std::option::Option<::std::string::String>,
    pub(crate) assistant_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ai_guardrail_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ai_guardrail_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) visibility_status: ::std::option::Option<crate::types::VisibilityStatus>,
    pub(crate) blocked_input_messaging: ::std::option::Option<::std::string::String>,
    pub(crate) blocked_outputs_messaging: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) topic_policy_config: ::std::option::Option<crate::types::AiGuardrailTopicPolicyConfig>,
    pub(crate) content_policy_config: ::std::option::Option<crate::types::AiGuardrailContentPolicyConfig>,
    pub(crate) word_policy_config: ::std::option::Option<crate::types::AiGuardrailWordPolicyConfig>,
    pub(crate) sensitive_information_policy_config: ::std::option::Option<crate::types::AiGuardrailSensitiveInformationPolicyConfig>,
    pub(crate) contextual_grounding_policy_config: ::std::option::Option<crate::types::AiGuardrailContextualGroundingPolicyConfig>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AiGuardrailDataBuilder {
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    /// This field is required.
    pub fn assistant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assistant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn set_assistant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assistant_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn get_assistant_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.assistant_id
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    /// This field is required.
    pub fn assistant_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assistant_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub fn set_assistant_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assistant_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub fn get_assistant_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.assistant_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the AI Guardrail.</p>
    /// This field is required.
    pub fn ai_guardrail_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_guardrail_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AI Guardrail.</p>
    pub fn set_ai_guardrail_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_guardrail_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AI Guardrail.</p>
    pub fn get_ai_guardrail_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_guardrail_arn
    }
    /// <p>The identifier of the Amazon Q in Connect AI Guardrail.</p>
    /// This field is required.
    pub fn ai_guardrail_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_guardrail_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Guardrail.</p>
    pub fn set_ai_guardrail_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_guardrail_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Guardrail.</p>
    pub fn get_ai_guardrail_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_guardrail_id
    }
    /// <p>The name of the AI Guardrail.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the AI Guardrail.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the AI Guardrail.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The visibility status of the AI Guardrail.</p>
    /// This field is required.
    pub fn visibility_status(mut self, input: crate::types::VisibilityStatus) -> Self {
        self.visibility_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility status of the AI Guardrail.</p>
    pub fn set_visibility_status(mut self, input: ::std::option::Option<crate::types::VisibilityStatus>) -> Self {
        self.visibility_status = input;
        self
    }
    /// <p>The visibility status of the AI Guardrail.</p>
    pub fn get_visibility_status(&self) -> &::std::option::Option<crate::types::VisibilityStatus> {
        &self.visibility_status
    }
    /// <p>The message to return when the AI Guardrail blocks a prompt.</p>
    /// This field is required.
    pub fn blocked_input_messaging(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.blocked_input_messaging = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message to return when the AI Guardrail blocks a prompt.</p>
    pub fn set_blocked_input_messaging(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.blocked_input_messaging = input;
        self
    }
    /// <p>The message to return when the AI Guardrail blocks a prompt.</p>
    pub fn get_blocked_input_messaging(&self) -> &::std::option::Option<::std::string::String> {
        &self.blocked_input_messaging
    }
    /// <p>The message to return when the AI Guardrail blocks a model response.</p>
    /// This field is required.
    pub fn blocked_outputs_messaging(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.blocked_outputs_messaging = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message to return when the AI Guardrail blocks a model response.</p>
    pub fn set_blocked_outputs_messaging(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.blocked_outputs_messaging = input;
        self
    }
    /// <p>The message to return when the AI Guardrail blocks a model response.</p>
    pub fn get_blocked_outputs_messaging(&self) -> &::std::option::Option<::std::string::String> {
        &self.blocked_outputs_messaging
    }
    /// <p>A description of the AI Guardrail.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the AI Guardrail.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the AI Guardrail.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Contains details about topics that the AI Guardrail should identify and deny.</p>
    pub fn topic_policy_config(mut self, input: crate::types::AiGuardrailTopicPolicyConfig) -> Self {
        self.topic_policy_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about topics that the AI Guardrail should identify and deny.</p>
    pub fn set_topic_policy_config(mut self, input: ::std::option::Option<crate::types::AiGuardrailTopicPolicyConfig>) -> Self {
        self.topic_policy_config = input;
        self
    }
    /// <p>Contains details about topics that the AI Guardrail should identify and deny.</p>
    pub fn get_topic_policy_config(&self) -> &::std::option::Option<crate::types::AiGuardrailTopicPolicyConfig> {
        &self.topic_policy_config
    }
    /// <p>Contains details about how to handle harmful content.</p>
    pub fn content_policy_config(mut self, input: crate::types::AiGuardrailContentPolicyConfig) -> Self {
        self.content_policy_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about how to handle harmful content.</p>
    pub fn set_content_policy_config(mut self, input: ::std::option::Option<crate::types::AiGuardrailContentPolicyConfig>) -> Self {
        self.content_policy_config = input;
        self
    }
    /// <p>Contains details about how to handle harmful content.</p>
    pub fn get_content_policy_config(&self) -> &::std::option::Option<crate::types::AiGuardrailContentPolicyConfig> {
        &self.content_policy_config
    }
    /// <p>Contains details about the word policy to configured for the AI Guardrail.</p>
    pub fn word_policy_config(mut self, input: crate::types::AiGuardrailWordPolicyConfig) -> Self {
        self.word_policy_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about the word policy to configured for the AI Guardrail.</p>
    pub fn set_word_policy_config(mut self, input: ::std::option::Option<crate::types::AiGuardrailWordPolicyConfig>) -> Self {
        self.word_policy_config = input;
        self
    }
    /// <p>Contains details about the word policy to configured for the AI Guardrail.</p>
    pub fn get_word_policy_config(&self) -> &::std::option::Option<crate::types::AiGuardrailWordPolicyConfig> {
        &self.word_policy_config
    }
    /// <p>Contains details about PII entities and regular expressions to configure for the AI Guardrail.</p>
    pub fn sensitive_information_policy_config(mut self, input: crate::types::AiGuardrailSensitiveInformationPolicyConfig) -> Self {
        self.sensitive_information_policy_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about PII entities and regular expressions to configure for the AI Guardrail.</p>
    pub fn set_sensitive_information_policy_config(
        mut self,
        input: ::std::option::Option<crate::types::AiGuardrailSensitiveInformationPolicyConfig>,
    ) -> Self {
        self.sensitive_information_policy_config = input;
        self
    }
    /// <p>Contains details about PII entities and regular expressions to configure for the AI Guardrail.</p>
    pub fn get_sensitive_information_policy_config(&self) -> &::std::option::Option<crate::types::AiGuardrailSensitiveInformationPolicyConfig> {
        &self.sensitive_information_policy_config
    }
    /// <p>The policy configuration details for the AI Guardrail's contextual grounding policy.</p>
    pub fn contextual_grounding_policy_config(mut self, input: crate::types::AiGuardrailContextualGroundingPolicyConfig) -> Self {
        self.contextual_grounding_policy_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The policy configuration details for the AI Guardrail's contextual grounding policy.</p>
    pub fn set_contextual_grounding_policy_config(
        mut self,
        input: ::std::option::Option<crate::types::AiGuardrailContextualGroundingPolicyConfig>,
    ) -> Self {
        self.contextual_grounding_policy_config = input;
        self
    }
    /// <p>The policy configuration details for the AI Guardrail's contextual grounding policy.</p>
    pub fn get_contextual_grounding_policy_config(&self) -> &::std::option::Option<crate::types::AiGuardrailContextualGroundingPolicyConfig> {
        &self.contextual_grounding_policy_config
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The status of the AI Guardrail.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the AI Guardrail.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the AI Guardrail.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>The time the AI Guardrail was last modified.</p>
    pub fn modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the AI Guardrail was last modified.</p>
    pub fn set_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_time = input;
        self
    }
    /// <p>The time the AI Guardrail was last modified.</p>
    pub fn get_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_time
    }
    /// Consumes the builder and constructs a [`AiGuardrailData`](crate::types::AiGuardrailData).
    /// This method will fail if any of the following fields are not set:
    /// - [`assistant_id`](crate::types::builders::AiGuardrailDataBuilder::assistant_id)
    /// - [`assistant_arn`](crate::types::builders::AiGuardrailDataBuilder::assistant_arn)
    /// - [`ai_guardrail_arn`](crate::types::builders::AiGuardrailDataBuilder::ai_guardrail_arn)
    /// - [`ai_guardrail_id`](crate::types::builders::AiGuardrailDataBuilder::ai_guardrail_id)
    /// - [`name`](crate::types::builders::AiGuardrailDataBuilder::name)
    /// - [`visibility_status`](crate::types::builders::AiGuardrailDataBuilder::visibility_status)
    /// - [`blocked_input_messaging`](crate::types::builders::AiGuardrailDataBuilder::blocked_input_messaging)
    /// - [`blocked_outputs_messaging`](crate::types::builders::AiGuardrailDataBuilder::blocked_outputs_messaging)
    pub fn build(self) -> ::std::result::Result<crate::types::AiGuardrailData, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AiGuardrailData {
            assistant_id: self.assistant_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_id",
                    "assistant_id was not specified but it is required when building AiGuardrailData",
                )
            })?,
            assistant_arn: self.assistant_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_arn",
                    "assistant_arn was not specified but it is required when building AiGuardrailData",
                )
            })?,
            ai_guardrail_arn: self.ai_guardrail_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ai_guardrail_arn",
                    "ai_guardrail_arn was not specified but it is required when building AiGuardrailData",
                )
            })?,
            ai_guardrail_id: self.ai_guardrail_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ai_guardrail_id",
                    "ai_guardrail_id was not specified but it is required when building AiGuardrailData",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AiGuardrailData",
                )
            })?,
            visibility_status: self.visibility_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "visibility_status",
                    "visibility_status was not specified but it is required when building AiGuardrailData",
                )
            })?,
            blocked_input_messaging: self.blocked_input_messaging.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "blocked_input_messaging",
                    "blocked_input_messaging was not specified but it is required when building AiGuardrailData",
                )
            })?,
            blocked_outputs_messaging: self.blocked_outputs_messaging.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "blocked_outputs_messaging",
                    "blocked_outputs_messaging was not specified but it is required when building AiGuardrailData",
                )
            })?,
            description: self.description,
            topic_policy_config: self.topic_policy_config,
            content_policy_config: self.content_policy_config,
            word_policy_config: self.word_policy_config,
            sensitive_information_policy_config: self.sensitive_information_policy_config,
            contextual_grounding_policy_config: self.contextual_grounding_policy_config,
            tags: self.tags,
            status: self.status,
            modified_time: self.modified_time,
        })
    }
}
impl ::std::fmt::Debug for AiGuardrailDataBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AiGuardrailDataBuilder");
        formatter.field("assistant_id", &self.assistant_id);
        formatter.field("assistant_arn", &self.assistant_arn);
        formatter.field("ai_guardrail_arn", &self.ai_guardrail_arn);
        formatter.field("ai_guardrail_id", &self.ai_guardrail_id);
        formatter.field("name", &self.name);
        formatter.field("visibility_status", &self.visibility_status);
        formatter.field("blocked_input_messaging", &"*** Sensitive Data Redacted ***");
        formatter.field("blocked_outputs_messaging", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("topic_policy_config", &self.topic_policy_config);
        formatter.field("content_policy_config", &self.content_policy_config);
        formatter.field("word_policy_config", &self.word_policy_config);
        formatter.field("sensitive_information_policy_config", &self.sensitive_information_policy_config);
        formatter.field("contextual_grounding_policy_config", &self.contextual_grounding_policy_config);
        formatter.field("tags", &self.tags);
        formatter.field("status", &self.status);
        formatter.field("modified_time", &self.modified_time);
        formatter.finish()
    }
}
