// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAiPromptInput {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="http://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>..</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub assistant_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Q in Connect AI Prompt.</p>
    pub ai_prompt_id: ::std::option::Option<::std::string::String>,
    /// <p>The visibility status of the Amazon Q in Connect AI prompt.</p>
    pub visibility_status: ::std::option::Option<crate::types::VisibilityStatus>,
    /// <p>The configuration of the prompt template for this AI Prompt.</p>
    pub template_configuration: ::std::option::Option<crate::types::AiPromptTemplateConfiguration>,
    /// <p>The description of the Amazon Q in Connect AI Prompt.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateAiPromptInput {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="http://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>..</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The identifier of the Amazon Q in Connect assistant. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn assistant_id(&self) -> ::std::option::Option<&str> {
        self.assistant_id.as_deref()
    }
    /// <p>The identifier of the Amazon Q in Connect AI Prompt.</p>
    pub fn ai_prompt_id(&self) -> ::std::option::Option<&str> {
        self.ai_prompt_id.as_deref()
    }
    /// <p>The visibility status of the Amazon Q in Connect AI prompt.</p>
    pub fn visibility_status(&self) -> ::std::option::Option<&crate::types::VisibilityStatus> {
        self.visibility_status.as_ref()
    }
    /// <p>The configuration of the prompt template for this AI Prompt.</p>
    pub fn template_configuration(&self) -> ::std::option::Option<&crate::types::AiPromptTemplateConfiguration> {
        self.template_configuration.as_ref()
    }
    /// <p>The description of the Amazon Q in Connect AI Prompt.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateAiPromptInput {
    /// Creates a new builder-style object to manufacture [`UpdateAiPromptInput`](crate::operation::update_ai_prompt::UpdateAiPromptInput).
    pub fn builder() -> crate::operation::update_ai_prompt::builders::UpdateAiPromptInputBuilder {
        crate::operation::update_ai_prompt::builders::UpdateAiPromptInputBuilder::default()
    }
}

/// A builder for [`UpdateAiPromptInput`](crate::operation::update_ai_prompt::UpdateAiPromptInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAiPromptInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) assistant_id: ::std::option::Option<::std::string::String>,
    pub(crate) ai_prompt_id: ::std::option::Option<::std::string::String>,
    pub(crate) visibility_status: ::std::option::Option<crate::types::VisibilityStatus>,
    pub(crate) template_configuration: ::std::option::Option<crate::types::AiPromptTemplateConfiguration>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateAiPromptInputBuilder {
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="http://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>..</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="http://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>..</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="http://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>..</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
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
    /// <p>The identifier of the Amazon Q in Connect AI Prompt.</p>
    /// This field is required.
    pub fn ai_prompt_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ai_prompt_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Prompt.</p>
    pub fn set_ai_prompt_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ai_prompt_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q in Connect AI Prompt.</p>
    pub fn get_ai_prompt_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ai_prompt_id
    }
    /// <p>The visibility status of the Amazon Q in Connect AI prompt.</p>
    /// This field is required.
    pub fn visibility_status(mut self, input: crate::types::VisibilityStatus) -> Self {
        self.visibility_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility status of the Amazon Q in Connect AI prompt.</p>
    pub fn set_visibility_status(mut self, input: ::std::option::Option<crate::types::VisibilityStatus>) -> Self {
        self.visibility_status = input;
        self
    }
    /// <p>The visibility status of the Amazon Q in Connect AI prompt.</p>
    pub fn get_visibility_status(&self) -> &::std::option::Option<crate::types::VisibilityStatus> {
        &self.visibility_status
    }
    /// <p>The configuration of the prompt template for this AI Prompt.</p>
    pub fn template_configuration(mut self, input: crate::types::AiPromptTemplateConfiguration) -> Self {
        self.template_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration of the prompt template for this AI Prompt.</p>
    pub fn set_template_configuration(mut self, input: ::std::option::Option<crate::types::AiPromptTemplateConfiguration>) -> Self {
        self.template_configuration = input;
        self
    }
    /// <p>The configuration of the prompt template for this AI Prompt.</p>
    pub fn get_template_configuration(&self) -> &::std::option::Option<crate::types::AiPromptTemplateConfiguration> {
        &self.template_configuration
    }
    /// <p>The description of the Amazon Q in Connect AI Prompt.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the Amazon Q in Connect AI Prompt.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the Amazon Q in Connect AI Prompt.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateAiPromptInput`](crate::operation::update_ai_prompt::UpdateAiPromptInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_ai_prompt::UpdateAiPromptInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_ai_prompt::UpdateAiPromptInput {
            client_token: self.client_token,
            assistant_id: self.assistant_id,
            ai_prompt_id: self.ai_prompt_id,
            visibility_status: self.visibility_status,
            template_configuration: self.template_configuration,
            description: self.description,
        })
    }
}
