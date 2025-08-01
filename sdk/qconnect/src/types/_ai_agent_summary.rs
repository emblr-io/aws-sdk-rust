// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of the AI Agent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AiAgentSummary {
    /// <p>The name of the AI Agent.</p>
    pub name: ::std::string::String,
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub assistant_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the Amazon Q in Connect assistant.</p>
    pub assistant_arn: ::std::string::String,
    /// <p>The identifier of the AI Agent.</p>
    pub ai_agent_id: ::std::string::String,
    /// <p>The type of the AI Agent.</p>
    pub r#type: crate::types::AiAgentType,
    /// <p>The Amazon Resource Name (ARN) of the AI agent.</p>
    pub ai_agent_arn: ::std::string::String,
    /// <p>The time the AI Agent was last modified.</p>
    pub modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The visibility status of the AI Agent.</p>
    pub visibility_status: crate::types::VisibilityStatus,
    /// <p>The configuration for the AI Agent.</p>
    pub configuration: ::std::option::Option<crate::types::AiAgentConfiguration>,
    /// <p>The origin of the AI Agent. <code>SYSTEM</code> for a default AI Agent created by Q in Connect or <code>CUSTOMER</code> for an AI Agent created by calling AI Agent creation APIs.</p>
    pub origin: ::std::option::Option<crate::types::Origin>,
    /// <p>The description of the AI Agent.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The status of the AI Agent.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AiAgentSummary {
    /// <p>The name of the AI Agent.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
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
    /// <p>The identifier of the AI Agent.</p>
    pub fn ai_agent_id(&self) -> &str {
        use std::ops::Deref;
        self.ai_agent_id.deref()
    }
    /// <p>The type of the AI Agent.</p>
    pub fn r#type(&self) -> &crate::types::AiAgentType {
        &self.r#type
    }
    /// <p>The Amazon Resource Name (ARN) of the AI agent.</p>
    pub fn ai_agent_arn(&self) -> &str {
        use std::ops::Deref;
        self.ai_agent_arn.deref()
    }
    /// <p>The time the AI Agent was last modified.</p>
    pub fn modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_time.as_ref()
    }
    /// <p>The visibility status of the AI Agent.</p>
    pub fn visibility_status(&self) -> &crate::types::VisibilityStatus {
        &self.visibility_status
    }
    /// <p>The configuration for the AI Agent.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::AiAgentConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>The origin of the AI Agent. <code>SYSTEM</code> for a default AI Agent created by Q in Connect or <code>CUSTOMER</code> for an AI Agent created by calling AI Agent creation APIs.</p>
    pub fn origin(&self) -> ::std::option::Option<&crate::types::Origin> {
        self.origin.as_ref()
    }
    /// <p>The description of the AI Agent.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The status of the AI Agent.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl AiAgentSummary {
    /// Creates a new builder-style object to manufacture [`AiAgentSummary`](crate::types::AiAgentSummary).
    pub fn builder() -> crate::types::builders::AiAgentSummaryBuilder {
        crate::types::builders::AiAgentSummaryBuilder::default()
    }
}

/// A builder for [`AiAgentSummary`](crate::types::AiAgentSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AiAgentSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) assistant_id: ::std::option::Option<::std::string::String>,
    pub(crate) assistant_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ai_agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::AiAgentType>,
    pub(crate) ai_agent_arn: ::std::option::Option<::std::string::String>,
    pub(crate) modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) visibility_status: ::std::option::Option<crate::types::VisibilityStatus>,
    pub(crate) configuration: ::std::option::Option<crate::types::AiAgentConfiguration>,
    pub(crate) origin: ::std::option::Option<crate::types::Origin>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AiAgentSummaryBuilder {
    /// <p>The name of the AI Agent.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the AI Agent.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the AI Agent.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
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
    /// <p>The identifier of the AI Agent.</p>
    /// This field is required.
    pub fn ai_agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the AI Agent.</p>
    pub fn set_ai_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_agent_id = input;
        self
    }
    /// <p>The identifier of the AI Agent.</p>
    pub fn get_ai_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_agent_id
    }
    /// <p>The type of the AI Agent.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::AiAgentType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the AI Agent.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AiAgentType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the AI Agent.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AiAgentType> {
        &self.r#type
    }
    /// <p>The Amazon Resource Name (ARN) of the AI agent.</p>
    /// This field is required.
    pub fn ai_agent_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_agent_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AI agent.</p>
    pub fn set_ai_agent_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_agent_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AI agent.</p>
    pub fn get_ai_agent_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_agent_arn
    }
    /// <p>The time the AI Agent was last modified.</p>
    pub fn modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the AI Agent was last modified.</p>
    pub fn set_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_time = input;
        self
    }
    /// <p>The time the AI Agent was last modified.</p>
    pub fn get_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_time
    }
    /// <p>The visibility status of the AI Agent.</p>
    /// This field is required.
    pub fn visibility_status(mut self, input: crate::types::VisibilityStatus) -> Self {
        self.visibility_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility status of the AI Agent.</p>
    pub fn set_visibility_status(mut self, input: ::std::option::Option<crate::types::VisibilityStatus>) -> Self {
        self.visibility_status = input;
        self
    }
    /// <p>The visibility status of the AI Agent.</p>
    pub fn get_visibility_status(&self) -> &::std::option::Option<crate::types::VisibilityStatus> {
        &self.visibility_status
    }
    /// <p>The configuration for the AI Agent.</p>
    pub fn configuration(mut self, input: crate::types::AiAgentConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the AI Agent.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::AiAgentConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The configuration for the AI Agent.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::AiAgentConfiguration> {
        &self.configuration
    }
    /// <p>The origin of the AI Agent. <code>SYSTEM</code> for a default AI Agent created by Q in Connect or <code>CUSTOMER</code> for an AI Agent created by calling AI Agent creation APIs.</p>
    pub fn origin(mut self, input: crate::types::Origin) -> Self {
        self.origin = ::std::option::Option::Some(input);
        self
    }
    /// <p>The origin of the AI Agent. <code>SYSTEM</code> for a default AI Agent created by Q in Connect or <code>CUSTOMER</code> for an AI Agent created by calling AI Agent creation APIs.</p>
    pub fn set_origin(mut self, input: ::std::option::Option<crate::types::Origin>) -> Self {
        self.origin = input;
        self
    }
    /// <p>The origin of the AI Agent. <code>SYSTEM</code> for a default AI Agent created by Q in Connect or <code>CUSTOMER</code> for an AI Agent created by calling AI Agent creation APIs.</p>
    pub fn get_origin(&self) -> &::std::option::Option<crate::types::Origin> {
        &self.origin
    }
    /// <p>The description of the AI Agent.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the AI Agent.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the AI Agent.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The status of the AI Agent.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the AI Agent.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the AI Agent.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
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
    /// Consumes the builder and constructs a [`AiAgentSummary`](crate::types::AiAgentSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AiAgentSummaryBuilder::name)
    /// - [`assistant_id`](crate::types::builders::AiAgentSummaryBuilder::assistant_id)
    /// - [`assistant_arn`](crate::types::builders::AiAgentSummaryBuilder::assistant_arn)
    /// - [`ai_agent_id`](crate::types::builders::AiAgentSummaryBuilder::ai_agent_id)
    /// - [`r#type`](crate::types::builders::AiAgentSummaryBuilder::type)
    /// - [`ai_agent_arn`](crate::types::builders::AiAgentSummaryBuilder::ai_agent_arn)
    /// - [`visibility_status`](crate::types::builders::AiAgentSummaryBuilder::visibility_status)
    pub fn build(self) -> ::std::result::Result<crate::types::AiAgentSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AiAgentSummary {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AiAgentSummary",
                )
            })?,
            assistant_id: self.assistant_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_id",
                    "assistant_id was not specified but it is required when building AiAgentSummary",
                )
            })?,
            assistant_arn: self.assistant_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "assistant_arn",
                    "assistant_arn was not specified but it is required when building AiAgentSummary",
                )
            })?,
            ai_agent_id: self.ai_agent_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ai_agent_id",
                    "ai_agent_id was not specified but it is required when building AiAgentSummary",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building AiAgentSummary",
                )
            })?,
            ai_agent_arn: self.ai_agent_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ai_agent_arn",
                    "ai_agent_arn was not specified but it is required when building AiAgentSummary",
                )
            })?,
            modified_time: self.modified_time,
            visibility_status: self.visibility_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "visibility_status",
                    "visibility_status was not specified but it is required when building AiAgentSummary",
                )
            })?,
            configuration: self.configuration,
            origin: self.origin,
            description: self.description,
            status: self.status,
            tags: self.tags,
        })
    }
}
