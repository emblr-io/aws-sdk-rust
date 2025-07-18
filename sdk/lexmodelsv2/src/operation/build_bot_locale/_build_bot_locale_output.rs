// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BuildBotLocaleOutput {
    /// <p>The identifier of the specified bot.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot that was built. This is only the draft version of the bot.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The language and locale specified of where the bot can be used.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>The bot's build status. When the status is <code>ReadyExpressTesting</code> you can test the bot using the utterances defined for the intents and slot types. When the status is <code>Built</code>, the bot is ready for use and can be tested using any utterance.</p>
    pub bot_locale_status: ::std::option::Option<crate::types::BotLocaleStatus>,
    /// <p>A timestamp indicating the date and time that the bot was last built for this locale.</p>
    pub last_build_submitted_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl BuildBotLocaleOutput {
    /// <p>The identifier of the specified bot.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot that was built. This is only the draft version of the bot.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The language and locale specified of where the bot can be used.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>The bot's build status. When the status is <code>ReadyExpressTesting</code> you can test the bot using the utterances defined for the intents and slot types. When the status is <code>Built</code>, the bot is ready for use and can be tested using any utterance.</p>
    pub fn bot_locale_status(&self) -> ::std::option::Option<&crate::types::BotLocaleStatus> {
        self.bot_locale_status.as_ref()
    }
    /// <p>A timestamp indicating the date and time that the bot was last built for this locale.</p>
    pub fn last_build_submitted_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_build_submitted_date_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for BuildBotLocaleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BuildBotLocaleOutput {
    /// Creates a new builder-style object to manufacture [`BuildBotLocaleOutput`](crate::operation::build_bot_locale::BuildBotLocaleOutput).
    pub fn builder() -> crate::operation::build_bot_locale::builders::BuildBotLocaleOutputBuilder {
        crate::operation::build_bot_locale::builders::BuildBotLocaleOutputBuilder::default()
    }
}

/// A builder for [`BuildBotLocaleOutput`](crate::operation::build_bot_locale::BuildBotLocaleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BuildBotLocaleOutputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_locale_status: ::std::option::Option<crate::types::BotLocaleStatus>,
    pub(crate) last_build_submitted_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl BuildBotLocaleOutputBuilder {
    /// <p>The identifier of the specified bot.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the specified bot.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier of the specified bot.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot that was built. This is only the draft version of the bot.</p>
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot that was built. This is only the draft version of the bot.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot that was built. This is only the draft version of the bot.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The language and locale specified of where the bot can be used.</p>
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language and locale specified of where the bot can be used.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The language and locale specified of where the bot can be used.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>The bot's build status. When the status is <code>ReadyExpressTesting</code> you can test the bot using the utterances defined for the intents and slot types. When the status is <code>Built</code>, the bot is ready for use and can be tested using any utterance.</p>
    pub fn bot_locale_status(mut self, input: crate::types::BotLocaleStatus) -> Self {
        self.bot_locale_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The bot's build status. When the status is <code>ReadyExpressTesting</code> you can test the bot using the utterances defined for the intents and slot types. When the status is <code>Built</code>, the bot is ready for use and can be tested using any utterance.</p>
    pub fn set_bot_locale_status(mut self, input: ::std::option::Option<crate::types::BotLocaleStatus>) -> Self {
        self.bot_locale_status = input;
        self
    }
    /// <p>The bot's build status. When the status is <code>ReadyExpressTesting</code> you can test the bot using the utterances defined for the intents and slot types. When the status is <code>Built</code>, the bot is ready for use and can be tested using any utterance.</p>
    pub fn get_bot_locale_status(&self) -> &::std::option::Option<crate::types::BotLocaleStatus> {
        &self.bot_locale_status
    }
    /// <p>A timestamp indicating the date and time that the bot was last built for this locale.</p>
    pub fn last_build_submitted_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_build_submitted_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp indicating the date and time that the bot was last built for this locale.</p>
    pub fn set_last_build_submitted_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_build_submitted_date_time = input;
        self
    }
    /// <p>A timestamp indicating the date and time that the bot was last built for this locale.</p>
    pub fn get_last_build_submitted_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_build_submitted_date_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BuildBotLocaleOutput`](crate::operation::build_bot_locale::BuildBotLocaleOutput).
    pub fn build(self) -> crate::operation::build_bot_locale::BuildBotLocaleOutput {
        crate::operation::build_bot_locale::BuildBotLocaleOutput {
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            bot_locale_status: self.bot_locale_status,
            last_build_submitted_date_time: self.last_build_submitted_date_time,
            _request_id: self._request_id,
        }
    }
}
