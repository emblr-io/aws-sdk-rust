// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about the assistant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssistantSummary {
    /// <p>The identifier of the Amazon Q in Connect assistant.</p>
    pub assistant_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub assistant_arn: ::std::string::String,
    /// <p>The name of the assistant.</p>
    pub name: ::std::string::String,
    /// <p>The type of the assistant.</p>
    pub r#type: crate::types::AssistantType,
    /// <p>The status of the assistant.</p>
    pub status: crate::types::AssistantStatus,
    /// <p>The description of the assistant.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The configuration information for the customer managed key used for encryption.</p>
    /// <p>This KMS key must have a policy that allows <code>kms:CreateGrant</code>, <code>kms:DescribeKey</code>, <code>kms:Decrypt</code>, and <code>kms:GenerateDataKey*</code> permissions to the IAM identity using the key to invoke Amazon Q in Connect. To use Amazon Q in Connect with chat, the key policy must also allow <code>kms:Decrypt</code>, <code>kms:GenerateDataKey*</code>, and <code>kms:DescribeKey</code> permissions to the <code>connect.amazonaws.com</code> service principal.</p>
    /// <p>For more information about setting up a customer managed key for Amazon Q in Connect, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/enable-q.html">Enable Amazon Q in Connect for your instance</a>.</p>
    pub server_side_encryption_configuration: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>,
    /// <p>The configuration information for the Amazon Q in Connect assistant integration.</p>
    pub integration_configuration: ::std::option::Option<crate::types::AssistantIntegrationConfiguration>,
    /// <p>The configuration information for the Amazon Q in Connect assistant capability.</p>
    pub capability_configuration: ::std::option::Option<crate::types::AssistantCapabilityConfiguration>,
    /// <p>The configuration of the AI Agents (mapped by AI Agent Type to AI Agent version) that is set on the Amazon Q in Connect Assistant.</p>
    pub ai_agent_configuration: ::std::option::Option<::std::collections::HashMap<crate::types::AiAgentType, crate::types::AiAgentConfigurationData>>,
}
impl AssistantSummary {
    /// <p>The identifier of the Amazon Q in Connect assistant.</p>
    pub fn assistant_id(&self) -> &str {
        use std::ops::Deref;
        self.assistant_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub fn assistant_arn(&self) -> &str {
        use std::ops::Deref;
        self.assistant_arn.deref()
    }
    /// <p>The name of the assistant.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The type of the assistant.</p>
    pub fn r#type(&self) -> &crate::types::AssistantType {
        &self.r#type
    }
    /// <p>The status of the assistant.</p>
    pub fn status(&self) -> &crate::types::AssistantStatus {
        &self.status
    }
    /// <p>The description of the assistant.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The configuration information for the customer managed key used for encryption.</p>
    /// <p>This KMS key must have a policy that allows <code>kms:CreateGrant</code>, <code>kms:DescribeKey</code>, <code>kms:Decrypt</code>, and <code>kms:GenerateDataKey*</code> permissions to the IAM identity using the key to invoke Amazon Q in Connect. To use Amazon Q in Connect with chat, the key policy must also allow <code>kms:Decrypt</code>, <code>kms:GenerateDataKey*</code>, and <code>kms:DescribeKey</code> permissions to the <code>connect.amazonaws.com</code> service principal.</p>
    /// <p>For more information about setting up a customer managed key for Amazon Q in Connect, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/enable-q.html">Enable Amazon Q in Connect for your instance</a>.</p>
    pub fn server_side_encryption_configuration(&self) -> ::std::option::Option<&crate::types::ServerSideEncryptionConfiguration> {
        self.server_side_encryption_configuration.as_ref()
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant integration.</p>
    pub fn integration_configuration(&self) -> ::std::option::Option<&crate::types::AssistantIntegrationConfiguration> {
        self.integration_configuration.as_ref()
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant capability.</p>
    pub fn capability_configuration(&self) -> ::std::option::Option<&crate::types::AssistantCapabilityConfiguration> {
        self.capability_configuration.as_ref()
    }
    /// <p>The configuration of the AI Agents (mapped by AI Agent Type to AI Agent version) that is set on the Amazon Q in Connect Assistant.</p>
    pub fn ai_agent_configuration(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<crate::types::AiAgentType, crate::types::AiAgentConfigurationData>> {
        self.ai_agent_configuration.as_ref()
    }
}
impl AssistantSummary {
    /// Creates a new builder-style object to manufacture [`AssistantSummary`](crate::types::AssistantSummary).
    pub fn builder() -> crate::types::builders::AssistantSummaryBuilder {
        crate::types::builders::AssistantSummaryBuilder::default()
    }
}

/// A builder for [`AssistantSummary`](crate::types::AssistantSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssistantSummaryBuilder {
    pub(crate) assistant_id: ::std::option::Option<::std::string::String>,
    pub(crate) assistant_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::AssistantType>,
    pub(crate) status: ::std::option::Option<crate::types::AssistantStatus>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) server_side_encryption_configuration: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>,
    pub(crate) integration_configuration: ::std::option::Option<crate::types::AssistantIntegrationConfiguration>,
    pub(crate) capability_configuration: ::std::option::Option<crate::types::AssistantCapabilityConfiguration>,
    pub(crate) ai_agent_configuration:
        ::std::option::Option<::std::collections::HashMap<crate::types::AiAgentType, crate::types::AiAgentConfigurationData>>,
}
impl AssistantSummaryBuilder {
    /// <p>The identifier of the Amazon Q in Connect assistant.</p>
    /// This field is required.
    pub fn assistant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assistant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q in Connect assistant.</p>
    pub fn set_assistant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assistant_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q in Connect assistant.</p>
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
    /// <p>The name of the assistant.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the assistant.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the assistant.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of the assistant.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::AssistantType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the assistant.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AssistantType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the assistant.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AssistantType> {
        &self.r#type
    }
    /// <p>The status of the assistant.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::AssistantStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the assistant.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AssistantStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the assistant.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AssistantStatus> {
        &self.status
    }
    /// <p>The description of the assistant.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the assistant.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the assistant.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
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
    /// <p>The configuration information for the customer managed key used for encryption.</p>
    /// <p>This KMS key must have a policy that allows <code>kms:CreateGrant</code>, <code>kms:DescribeKey</code>, <code>kms:Decrypt</code>, and <code>kms:GenerateDataKey*</code> permissions to the IAM identity using the key to invoke Amazon Q in Connect. To use Amazon Q in Connect with chat, the key policy must also allow <code>kms:Decrypt</code>, <code>kms:GenerateDataKey*</code>, and <code>kms:DescribeKey</code> permissions to the <code>connect.amazonaws.com</code> service principal.</p>
    /// <p>For more information about setting up a customer managed key for Amazon Q in Connect, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/enable-q.html">Enable Amazon Q in Connect for your instance</a>.</p>
    pub fn server_side_encryption_configuration(mut self, input: crate::types::ServerSideEncryptionConfiguration) -> Self {
        self.server_side_encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for the customer managed key used for encryption.</p>
    /// <p>This KMS key must have a policy that allows <code>kms:CreateGrant</code>, <code>kms:DescribeKey</code>, <code>kms:Decrypt</code>, and <code>kms:GenerateDataKey*</code> permissions to the IAM identity using the key to invoke Amazon Q in Connect. To use Amazon Q in Connect with chat, the key policy must also allow <code>kms:Decrypt</code>, <code>kms:GenerateDataKey*</code>, and <code>kms:DescribeKey</code> permissions to the <code>connect.amazonaws.com</code> service principal.</p>
    /// <p>For more information about setting up a customer managed key for Amazon Q in Connect, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/enable-q.html">Enable Amazon Q in Connect for your instance</a>.</p>
    pub fn set_server_side_encryption_configuration(mut self, input: ::std::option::Option<crate::types::ServerSideEncryptionConfiguration>) -> Self {
        self.server_side_encryption_configuration = input;
        self
    }
    /// <p>The configuration information for the customer managed key used for encryption.</p>
    /// <p>This KMS key must have a policy that allows <code>kms:CreateGrant</code>, <code>kms:DescribeKey</code>, <code>kms:Decrypt</code>, and <code>kms:GenerateDataKey*</code> permissions to the IAM identity using the key to invoke Amazon Q in Connect. To use Amazon Q in Connect with chat, the key policy must also allow <code>kms:Decrypt</code>, <code>kms:GenerateDataKey*</code>, and <code>kms:DescribeKey</code> permissions to the <code>connect.amazonaws.com</code> service principal.</p>
    /// <p>For more information about setting up a customer managed key for Amazon Q in Connect, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/enable-q.html">Enable Amazon Q in Connect for your instance</a>.</p>
    pub fn get_server_side_encryption_configuration(&self) -> &::std::option::Option<crate::types::ServerSideEncryptionConfiguration> {
        &self.server_side_encryption_configuration
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant integration.</p>
    pub fn integration_configuration(mut self, input: crate::types::AssistantIntegrationConfiguration) -> Self {
        self.integration_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant integration.</p>
    pub fn set_integration_configuration(mut self, input: ::std::option::Option<crate::types::AssistantIntegrationConfiguration>) -> Self {
        self.integration_configuration = input;
        self
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant integration.</p>
    pub fn get_integration_configuration(&self) -> &::std::option::Option<crate::types::AssistantIntegrationConfiguration> {
        &self.integration_configuration
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant capability.</p>
    pub fn capability_configuration(mut self, input: crate::types::AssistantCapabilityConfiguration) -> Self {
        self.capability_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant capability.</p>
    pub fn set_capability_configuration(mut self, input: ::std::option::Option<crate::types::AssistantCapabilityConfiguration>) -> Self {
        self.capability_configuration = input;
        self
    }
    /// <p>The configuration information for the Amazon Q in Connect assistant capability.</p>
    pub fn get_capability_configuration(&self) -> &::std::option::Option<crate::types::AssistantCapabilityConfiguration> {
        &self.capability_configuration
    }
    /// Adds a key-value pair to `ai_agent_configuration`.
    ///
    /// To override the contents of this collection use [`set_ai_agent_configuration`](Self::set_ai_agent_configuration).
    ///
    /// <p>The configuration of the AI Agents (mapped by AI Agent Type to AI Agent version) that is set on the Amazon Q in Connect Assistant.</p>
    pub fn ai_agent_configuration(mut self, k: crate::types::AiAgentType, v: crate::types::AiAgentConfigurationData) -> Self {
        let mut hash_map = self.ai_agent_configuration.unwrap_or_default();
        hash_map.insert(k, v);
        self.ai_agent_configuration = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The configuration of the AI Agents (mapped by AI Agent Type to AI Agent version) that is set on the Amazon Q in Connect Assistant.</p>
    pub fn set_ai_agent_configuration(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<crate::types::AiAgentType, crate::types::AiAgentConfigurationData>>,
    ) -> Self {
        self.ai_agent_configuration = input;
        self
    }
    /// <p>The configuration of the AI Agents (mapped by AI Agent Type to AI Agent version) that is set on the Amazon Q in Connect Assistant.</p>
    pub fn get_ai_agent_configuration(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<crate::types::AiAgentType, crate::types::AiAgentConfigurationData>> {
        &self.ai_agent_configuration
    }
    /// Consumes the builder and constructs a [`AssistantSummary`](crate::types::AssistantSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`assistant_id`](crate::types::builders::AssistantSummaryBuilder::assistant_id)
    /// - [`assistant_arn`](crate::types::builders::AssistantSummaryBuilder::assistant_arn)
    /// - [`name`](crate::types::builders::AssistantSummaryBuilder::name)
    /// - [`r#type`](crate::types::builders::AssistantSummaryBuilder::type)
    /// - [`status`](crate::types::builders::AssistantSummaryBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::AssistantSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssistantSummary {
            assistant_id: self.assistant_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_id",
                    "assistant_id was not specified but it is required when building AssistantSummary",
                )
            })?,
            assistant_arn: self.assistant_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_arn",
                    "assistant_arn was not specified but it is required when building AssistantSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AssistantSummary",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building AssistantSummary",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building AssistantSummary",
                )
            })?,
            description: self.description,
            tags: self.tags,
            server_side_encryption_configuration: self.server_side_encryption_configuration,
            integration_configuration: self.integration_configuration,
            capability_configuration: self.capability_configuration,
            ai_agent_configuration: self.ai_agent_configuration,
        })
    }
}
