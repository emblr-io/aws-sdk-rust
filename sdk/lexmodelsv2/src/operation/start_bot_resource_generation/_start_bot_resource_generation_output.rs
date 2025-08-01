// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartBotResourceGenerationOutput {
    /// <p>The prompt that was used generate intents and slot types for the bot locale.</p>
    pub generation_input_prompt: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the generation request.</p>
    pub generation_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the bot for which the generation request was made.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot for which the generation request was made.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The locale of the bot for which the generation request was made.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the generation request.</p>
    pub generation_status: ::std::option::Option<crate::types::GenerationStatus>,
    /// <p>The date and time at which the generation request was made.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StartBotResourceGenerationOutput {
    /// <p>The prompt that was used generate intents and slot types for the bot locale.</p>
    pub fn generation_input_prompt(&self) -> ::std::option::Option<&str> {
        self.generation_input_prompt.as_deref()
    }
    /// <p>The unique identifier of the generation request.</p>
    pub fn generation_id(&self) -> ::std::option::Option<&str> {
        self.generation_id.as_deref()
    }
    /// <p>The unique identifier of the bot for which the generation request was made.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot for which the generation request was made.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The locale of the bot for which the generation request was made.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>The status of the generation request.</p>
    pub fn generation_status(&self) -> ::std::option::Option<&crate::types::GenerationStatus> {
        self.generation_status.as_ref()
    }
    /// <p>The date and time at which the generation request was made.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StartBotResourceGenerationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartBotResourceGenerationOutput {
    /// Creates a new builder-style object to manufacture [`StartBotResourceGenerationOutput`](crate::operation::start_bot_resource_generation::StartBotResourceGenerationOutput).
    pub fn builder() -> crate::operation::start_bot_resource_generation::builders::StartBotResourceGenerationOutputBuilder {
        crate::operation::start_bot_resource_generation::builders::StartBotResourceGenerationOutputBuilder::default()
    }
}

/// A builder for [`StartBotResourceGenerationOutput`](crate::operation::start_bot_resource_generation::StartBotResourceGenerationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartBotResourceGenerationOutputBuilder {
    pub(crate) generation_input_prompt: ::std::option::Option<::std::string::String>,
    pub(crate) generation_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) generation_status: ::std::option::Option<crate::types::GenerationStatus>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StartBotResourceGenerationOutputBuilder {
    /// <p>The prompt that was used generate intents and slot types for the bot locale.</p>
    pub fn generation_input_prompt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.generation_input_prompt = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prompt that was used generate intents and slot types for the bot locale.</p>
    pub fn set_generation_input_prompt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.generation_input_prompt = input;
        self
    }
    /// <p>The prompt that was used generate intents and slot types for the bot locale.</p>
    pub fn get_generation_input_prompt(&self) -> &::std::option::Option<::std::string::String> {
        &self.generation_input_prompt
    }
    /// <p>The unique identifier of the generation request.</p>
    pub fn generation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.generation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the generation request.</p>
    pub fn set_generation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.generation_id = input;
        self
    }
    /// <p>The unique identifier of the generation request.</p>
    pub fn get_generation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.generation_id
    }
    /// <p>The unique identifier of the bot for which the generation request was made.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the bot for which the generation request was made.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The unique identifier of the bot for which the generation request was made.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot for which the generation request was made.</p>
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot for which the generation request was made.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot for which the generation request was made.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The locale of the bot for which the generation request was made.</p>
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The locale of the bot for which the generation request was made.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The locale of the bot for which the generation request was made.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>The status of the generation request.</p>
    pub fn generation_status(mut self, input: crate::types::GenerationStatus) -> Self {
        self.generation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the generation request.</p>
    pub fn set_generation_status(mut self, input: ::std::option::Option<crate::types::GenerationStatus>) -> Self {
        self.generation_status = input;
        self
    }
    /// <p>The status of the generation request.</p>
    pub fn get_generation_status(&self) -> &::std::option::Option<crate::types::GenerationStatus> {
        &self.generation_status
    }
    /// <p>The date and time at which the generation request was made.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the generation request was made.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The date and time at which the generation request was made.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartBotResourceGenerationOutput`](crate::operation::start_bot_resource_generation::StartBotResourceGenerationOutput).
    pub fn build(self) -> crate::operation::start_bot_resource_generation::StartBotResourceGenerationOutput {
        crate::operation::start_bot_resource_generation::StartBotResourceGenerationOutput {
            generation_input_prompt: self.generation_input_prompt,
            generation_id: self.generation_id,
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            generation_status: self.generation_status,
            creation_date_time: self.creation_date_time,
            _request_id: self._request_id,
        }
    }
}
