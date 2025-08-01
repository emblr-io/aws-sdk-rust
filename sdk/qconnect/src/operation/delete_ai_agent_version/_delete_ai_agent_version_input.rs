// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAiAgentVersionInput {
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub assistant_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Q in Connect AI Agent. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub ai_agent_id: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the AI Agent version.</p>
    pub version_number: ::std::option::Option<i64>,
}
impl DeleteAiAgentVersionInput {
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn assistant_id(&self) -> ::std::option::Option<&str> {
        self.assistant_id.as_deref()
    }
    /// <p>The identifier of the Amazon Q in Connect AI Agent. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn ai_agent_id(&self) -> ::std::option::Option<&str> {
        self.ai_agent_id.as_deref()
    }
    /// <p>The version number of the AI Agent version.</p>
    pub fn version_number(&self) -> ::std::option::Option<i64> {
        self.version_number
    }
}
impl DeleteAiAgentVersionInput {
    /// Creates a new builder-style object to manufacture [`DeleteAiAgentVersionInput`](crate::operation::delete_ai_agent_version::DeleteAiAgentVersionInput).
    pub fn builder() -> crate::operation::delete_ai_agent_version::builders::DeleteAiAgentVersionInputBuilder {
        crate::operation::delete_ai_agent_version::builders::DeleteAiAgentVersionInputBuilder::default()
    }
}

/// A builder for [`DeleteAiAgentVersionInput`](crate::operation::delete_ai_agent_version::DeleteAiAgentVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAiAgentVersionInputBuilder {
    pub(crate) assistant_id: ::std::option::Option<::std::string::String>,
    pub(crate) ai_agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i64>,
}
impl DeleteAiAgentVersionInputBuilder {
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
    /// <p>The identifier of the Amazon Q in Connect AI Agent. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    /// This field is required.
    pub fn ai_agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Agent. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn set_ai_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_agent_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Agent. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn get_ai_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_agent_id
    }
    /// <p>The version number of the AI Agent version.</p>
    /// This field is required.
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the AI Agent version.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The version number of the AI Agent version.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    /// Consumes the builder and constructs a [`DeleteAiAgentVersionInput`](crate::operation::delete_ai_agent_version::DeleteAiAgentVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_ai_agent_version::DeleteAiAgentVersionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_ai_agent_version::DeleteAiAgentVersionInput {
            assistant_id: self.assistant_id,
            ai_agent_id: self.ai_agent_id,
            version_number: self.version_number,
        })
    }
}
