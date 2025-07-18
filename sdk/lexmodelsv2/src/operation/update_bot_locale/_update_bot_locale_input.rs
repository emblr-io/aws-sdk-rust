// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateBotLocaleInput {
    /// <p>The unique identifier of the bot that contains the locale.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot that contains the locale to be updated. The version can only be the <code>DRAFT</code> version.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the language and locale to update. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>The new description of the locale.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The new confidence threshold where Amazon Lex inserts the <code>AMAZON.FallbackIntent</code> and <code>AMAZON.KendraSearchIntent</code> intents in the list of possible intents for an utterance.</p>
    pub nlu_intent_confidence_threshold: ::std::option::Option<f64>,
    /// <p>The new Amazon Polly voice Amazon Lex should use for voice interaction with the user.</p>
    pub voice_settings: ::std::option::Option<crate::types::VoiceSettings>,
    /// <p>Contains settings for generative AI features powered by Amazon Bedrock for your bot locale. Use this object to turn generative AI features on and off. Pricing may differ if you turn a feature on. For more information, see LINK.</p>
    pub generative_ai_settings: ::std::option::Option<crate::types::GenerativeAiSettings>,
}
impl UpdateBotLocaleInput {
    /// <p>The unique identifier of the bot that contains the locale.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot that contains the locale to be updated. The version can only be the <code>DRAFT</code> version.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The identifier of the language and locale to update. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>The new description of the locale.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The new confidence threshold where Amazon Lex inserts the <code>AMAZON.FallbackIntent</code> and <code>AMAZON.KendraSearchIntent</code> intents in the list of possible intents for an utterance.</p>
    pub fn nlu_intent_confidence_threshold(&self) -> ::std::option::Option<f64> {
        self.nlu_intent_confidence_threshold
    }
    /// <p>The new Amazon Polly voice Amazon Lex should use for voice interaction with the user.</p>
    pub fn voice_settings(&self) -> ::std::option::Option<&crate::types::VoiceSettings> {
        self.voice_settings.as_ref()
    }
    /// <p>Contains settings for generative AI features powered by Amazon Bedrock for your bot locale. Use this object to turn generative AI features on and off. Pricing may differ if you turn a feature on. For more information, see LINK.</p>
    pub fn generative_ai_settings(&self) -> ::std::option::Option<&crate::types::GenerativeAiSettings> {
        self.generative_ai_settings.as_ref()
    }
}
impl UpdateBotLocaleInput {
    /// Creates a new builder-style object to manufacture [`UpdateBotLocaleInput`](crate::operation::update_bot_locale::UpdateBotLocaleInput).
    pub fn builder() -> crate::operation::update_bot_locale::builders::UpdateBotLocaleInputBuilder {
        crate::operation::update_bot_locale::builders::UpdateBotLocaleInputBuilder::default()
    }
}

/// A builder for [`UpdateBotLocaleInput`](crate::operation::update_bot_locale::UpdateBotLocaleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateBotLocaleInputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) nlu_intent_confidence_threshold: ::std::option::Option<f64>,
    pub(crate) voice_settings: ::std::option::Option<crate::types::VoiceSettings>,
    pub(crate) generative_ai_settings: ::std::option::Option<crate::types::GenerativeAiSettings>,
}
impl UpdateBotLocaleInputBuilder {
    /// <p>The unique identifier of the bot that contains the locale.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the bot that contains the locale.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The unique identifier of the bot that contains the locale.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot that contains the locale to be updated. The version can only be the <code>DRAFT</code> version.</p>
    /// This field is required.
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot that contains the locale to be updated. The version can only be the <code>DRAFT</code> version.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot that contains the locale to be updated. The version can only be the <code>DRAFT</code> version.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The identifier of the language and locale to update. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    /// This field is required.
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the language and locale to update. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The identifier of the language and locale to update. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>The new description of the locale.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description of the locale.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description of the locale.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The new confidence threshold where Amazon Lex inserts the <code>AMAZON.FallbackIntent</code> and <code>AMAZON.KendraSearchIntent</code> intents in the list of possible intents for an utterance.</p>
    /// This field is required.
    pub fn nlu_intent_confidence_threshold(mut self, input: f64) -> Self {
        self.nlu_intent_confidence_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new confidence threshold where Amazon Lex inserts the <code>AMAZON.FallbackIntent</code> and <code>AMAZON.KendraSearchIntent</code> intents in the list of possible intents for an utterance.</p>
    pub fn set_nlu_intent_confidence_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.nlu_intent_confidence_threshold = input;
        self
    }
    /// <p>The new confidence threshold where Amazon Lex inserts the <code>AMAZON.FallbackIntent</code> and <code>AMAZON.KendraSearchIntent</code> intents in the list of possible intents for an utterance.</p>
    pub fn get_nlu_intent_confidence_threshold(&self) -> &::std::option::Option<f64> {
        &self.nlu_intent_confidence_threshold
    }
    /// <p>The new Amazon Polly voice Amazon Lex should use for voice interaction with the user.</p>
    pub fn voice_settings(mut self, input: crate::types::VoiceSettings) -> Self {
        self.voice_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new Amazon Polly voice Amazon Lex should use for voice interaction with the user.</p>
    pub fn set_voice_settings(mut self, input: ::std::option::Option<crate::types::VoiceSettings>) -> Self {
        self.voice_settings = input;
        self
    }
    /// <p>The new Amazon Polly voice Amazon Lex should use for voice interaction with the user.</p>
    pub fn get_voice_settings(&self) -> &::std::option::Option<crate::types::VoiceSettings> {
        &self.voice_settings
    }
    /// <p>Contains settings for generative AI features powered by Amazon Bedrock for your bot locale. Use this object to turn generative AI features on and off. Pricing may differ if you turn a feature on. For more information, see LINK.</p>
    pub fn generative_ai_settings(mut self, input: crate::types::GenerativeAiSettings) -> Self {
        self.generative_ai_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains settings for generative AI features powered by Amazon Bedrock for your bot locale. Use this object to turn generative AI features on and off. Pricing may differ if you turn a feature on. For more information, see LINK.</p>
    pub fn set_generative_ai_settings(mut self, input: ::std::option::Option<crate::types::GenerativeAiSettings>) -> Self {
        self.generative_ai_settings = input;
        self
    }
    /// <p>Contains settings for generative AI features powered by Amazon Bedrock for your bot locale. Use this object to turn generative AI features on and off. Pricing may differ if you turn a feature on. For more information, see LINK.</p>
    pub fn get_generative_ai_settings(&self) -> &::std::option::Option<crate::types::GenerativeAiSettings> {
        &self.generative_ai_settings
    }
    /// Consumes the builder and constructs a [`UpdateBotLocaleInput`](crate::operation::update_bot_locale::UpdateBotLocaleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_bot_locale::UpdateBotLocaleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_bot_locale::UpdateBotLocaleInput {
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            description: self.description,
            nlu_intent_confidence_threshold: self.nlu_intent_confidence_threshold,
            voice_settings: self.voice_settings,
            generative_ai_settings: self.generative_ai_settings,
        })
    }
}
