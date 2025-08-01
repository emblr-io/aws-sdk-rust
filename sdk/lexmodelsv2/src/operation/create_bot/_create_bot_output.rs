// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBotOutput {
    /// <p>A unique identifier for a particular bot. You use this to identify the bot when you call other Amazon Lex API operations.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The name specified for the bot.</p>
    pub bot_name: ::std::option::Option<::std::string::String>,
    /// <p>The description specified for the bot.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The IAM role specified for the bot.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The data privacy settings specified for the bot.</p>
    pub data_privacy: ::std::option::Option<crate::types::DataPrivacy>,
    /// <p>The session idle time specified for the bot.</p>
    pub idle_session_ttl_in_seconds: ::std::option::Option<i32>,
    /// <p>Shows the current status of the bot. The bot is first in the <code>Creating</code> status. Once the bot is read for use, it changes to the <code>Available</code> status. After the bot is created, you can use the <code>DRAFT</code> version of the bot.</p>
    pub bot_status: ::std::option::Option<crate::types::BotStatus>,
    /// <p>A timestamp indicating the date and time that the bot was created.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of tags associated with the bot.</p>
    pub bot_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A list of tags associated with the test alias for the bot.</p>
    pub test_bot_alias_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The type of a bot that was created.</p>
    pub bot_type: ::std::option::Option<crate::types::BotType>,
    /// <p>The list of bots in a network that was created.</p>
    pub bot_members: ::std::option::Option<::std::vec::Vec<crate::types::BotMember>>,
    /// <p>Specifies configuration settings for delivering error logs to Cloudwatch Logs in an Amazon Lex bot response.</p>
    pub error_log_settings: ::std::option::Option<crate::types::ErrorLogSettings>,
    _request_id: Option<String>,
}
impl CreateBotOutput {
    /// <p>A unique identifier for a particular bot. You use this to identify the bot when you call other Amazon Lex API operations.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The name specified for the bot.</p>
    pub fn bot_name(&self) -> ::std::option::Option<&str> {
        self.bot_name.as_deref()
    }
    /// <p>The description specified for the bot.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The IAM role specified for the bot.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The data privacy settings specified for the bot.</p>
    pub fn data_privacy(&self) -> ::std::option::Option<&crate::types::DataPrivacy> {
        self.data_privacy.as_ref()
    }
    /// <p>The session idle time specified for the bot.</p>
    pub fn idle_session_ttl_in_seconds(&self) -> ::std::option::Option<i32> {
        self.idle_session_ttl_in_seconds
    }
    /// <p>Shows the current status of the bot. The bot is first in the <code>Creating</code> status. Once the bot is read for use, it changes to the <code>Available</code> status. After the bot is created, you can use the <code>DRAFT</code> version of the bot.</p>
    pub fn bot_status(&self) -> ::std::option::Option<&crate::types::BotStatus> {
        self.bot_status.as_ref()
    }
    /// <p>A timestamp indicating the date and time that the bot was created.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>A list of tags associated with the bot.</p>
    pub fn bot_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.bot_tags.as_ref()
    }
    /// <p>A list of tags associated with the test alias for the bot.</p>
    pub fn test_bot_alias_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.test_bot_alias_tags.as_ref()
    }
    /// <p>The type of a bot that was created.</p>
    pub fn bot_type(&self) -> ::std::option::Option<&crate::types::BotType> {
        self.bot_type.as_ref()
    }
    /// <p>The list of bots in a network that was created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bot_members.is_none()`.
    pub fn bot_members(&self) -> &[crate::types::BotMember] {
        self.bot_members.as_deref().unwrap_or_default()
    }
    /// <p>Specifies configuration settings for delivering error logs to Cloudwatch Logs in an Amazon Lex bot response.</p>
    pub fn error_log_settings(&self) -> ::std::option::Option<&crate::types::ErrorLogSettings> {
        self.error_log_settings.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateBotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateBotOutput {
    /// Creates a new builder-style object to manufacture [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
    pub fn builder() -> crate::operation::create_bot::builders::CreateBotOutputBuilder {
        crate::operation::create_bot::builders::CreateBotOutputBuilder::default()
    }
}

/// A builder for [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBotOutputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) data_privacy: ::std::option::Option<crate::types::DataPrivacy>,
    pub(crate) idle_session_ttl_in_seconds: ::std::option::Option<i32>,
    pub(crate) bot_status: ::std::option::Option<crate::types::BotStatus>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) bot_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) test_bot_alias_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) bot_type: ::std::option::Option<crate::types::BotType>,
    pub(crate) bot_members: ::std::option::Option<::std::vec::Vec<crate::types::BotMember>>,
    pub(crate) error_log_settings: ::std::option::Option<crate::types::ErrorLogSettings>,
    _request_id: Option<String>,
}
impl CreateBotOutputBuilder {
    /// <p>A unique identifier for a particular bot. You use this to identify the bot when you call other Amazon Lex API operations.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for a particular bot. You use this to identify the bot when you call other Amazon Lex API operations.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>A unique identifier for a particular bot. You use this to identify the bot when you call other Amazon Lex API operations.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The name specified for the bot.</p>
    pub fn bot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name specified for the bot.</p>
    pub fn set_bot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_name = input;
        self
    }
    /// <p>The name specified for the bot.</p>
    pub fn get_bot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_name
    }
    /// <p>The description specified for the bot.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description specified for the bot.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description specified for the bot.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The IAM role specified for the bot.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role specified for the bot.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The IAM role specified for the bot.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The data privacy settings specified for the bot.</p>
    pub fn data_privacy(mut self, input: crate::types::DataPrivacy) -> Self {
        self.data_privacy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data privacy settings specified for the bot.</p>
    pub fn set_data_privacy(mut self, input: ::std::option::Option<crate::types::DataPrivacy>) -> Self {
        self.data_privacy = input;
        self
    }
    /// <p>The data privacy settings specified for the bot.</p>
    pub fn get_data_privacy(&self) -> &::std::option::Option<crate::types::DataPrivacy> {
        &self.data_privacy
    }
    /// <p>The session idle time specified for the bot.</p>
    pub fn idle_session_ttl_in_seconds(mut self, input: i32) -> Self {
        self.idle_session_ttl_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The session idle time specified for the bot.</p>
    pub fn set_idle_session_ttl_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.idle_session_ttl_in_seconds = input;
        self
    }
    /// <p>The session idle time specified for the bot.</p>
    pub fn get_idle_session_ttl_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.idle_session_ttl_in_seconds
    }
    /// <p>Shows the current status of the bot. The bot is first in the <code>Creating</code> status. Once the bot is read for use, it changes to the <code>Available</code> status. After the bot is created, you can use the <code>DRAFT</code> version of the bot.</p>
    pub fn bot_status(mut self, input: crate::types::BotStatus) -> Self {
        self.bot_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Shows the current status of the bot. The bot is first in the <code>Creating</code> status. Once the bot is read for use, it changes to the <code>Available</code> status. After the bot is created, you can use the <code>DRAFT</code> version of the bot.</p>
    pub fn set_bot_status(mut self, input: ::std::option::Option<crate::types::BotStatus>) -> Self {
        self.bot_status = input;
        self
    }
    /// <p>Shows the current status of the bot. The bot is first in the <code>Creating</code> status. Once the bot is read for use, it changes to the <code>Available</code> status. After the bot is created, you can use the <code>DRAFT</code> version of the bot.</p>
    pub fn get_bot_status(&self) -> &::std::option::Option<crate::types::BotStatus> {
        &self.bot_status
    }
    /// <p>A timestamp indicating the date and time that the bot was created.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp indicating the date and time that the bot was created.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>A timestamp indicating the date and time that the bot was created.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// Adds a key-value pair to `bot_tags`.
    ///
    /// To override the contents of this collection use [`set_bot_tags`](Self::set_bot_tags).
    ///
    /// <p>A list of tags associated with the bot.</p>
    pub fn bot_tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.bot_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.bot_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of tags associated with the bot.</p>
    pub fn set_bot_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.bot_tags = input;
        self
    }
    /// <p>A list of tags associated with the bot.</p>
    pub fn get_bot_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.bot_tags
    }
    /// Adds a key-value pair to `test_bot_alias_tags`.
    ///
    /// To override the contents of this collection use [`set_test_bot_alias_tags`](Self::set_test_bot_alias_tags).
    ///
    /// <p>A list of tags associated with the test alias for the bot.</p>
    pub fn test_bot_alias_tags(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.test_bot_alias_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.test_bot_alias_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of tags associated with the test alias for the bot.</p>
    pub fn set_test_bot_alias_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.test_bot_alias_tags = input;
        self
    }
    /// <p>A list of tags associated with the test alias for the bot.</p>
    pub fn get_test_bot_alias_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.test_bot_alias_tags
    }
    /// <p>The type of a bot that was created.</p>
    pub fn bot_type(mut self, input: crate::types::BotType) -> Self {
        self.bot_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of a bot that was created.</p>
    pub fn set_bot_type(mut self, input: ::std::option::Option<crate::types::BotType>) -> Self {
        self.bot_type = input;
        self
    }
    /// <p>The type of a bot that was created.</p>
    pub fn get_bot_type(&self) -> &::std::option::Option<crate::types::BotType> {
        &self.bot_type
    }
    /// Appends an item to `bot_members`.
    ///
    /// To override the contents of this collection use [`set_bot_members`](Self::set_bot_members).
    ///
    /// <p>The list of bots in a network that was created.</p>
    pub fn bot_members(mut self, input: crate::types::BotMember) -> Self {
        let mut v = self.bot_members.unwrap_or_default();
        v.push(input);
        self.bot_members = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of bots in a network that was created.</p>
    pub fn set_bot_members(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BotMember>>) -> Self {
        self.bot_members = input;
        self
    }
    /// <p>The list of bots in a network that was created.</p>
    pub fn get_bot_members(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BotMember>> {
        &self.bot_members
    }
    /// <p>Specifies configuration settings for delivering error logs to Cloudwatch Logs in an Amazon Lex bot response.</p>
    pub fn error_log_settings(mut self, input: crate::types::ErrorLogSettings) -> Self {
        self.error_log_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies configuration settings for delivering error logs to Cloudwatch Logs in an Amazon Lex bot response.</p>
    pub fn set_error_log_settings(mut self, input: ::std::option::Option<crate::types::ErrorLogSettings>) -> Self {
        self.error_log_settings = input;
        self
    }
    /// <p>Specifies configuration settings for delivering error logs to Cloudwatch Logs in an Amazon Lex bot response.</p>
    pub fn get_error_log_settings(&self) -> &::std::option::Option<crate::types::ErrorLogSettings> {
        &self.error_log_settings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateBotOutput`](crate::operation::create_bot::CreateBotOutput).
    pub fn build(self) -> crate::operation::create_bot::CreateBotOutput {
        crate::operation::create_bot::CreateBotOutput {
            bot_id: self.bot_id,
            bot_name: self.bot_name,
            description: self.description,
            role_arn: self.role_arn,
            data_privacy: self.data_privacy,
            idle_session_ttl_in_seconds: self.idle_session_ttl_in_seconds,
            bot_status: self.bot_status,
            creation_date_time: self.creation_date_time,
            bot_tags: self.bot_tags,
            test_bot_alias_tags: self.test_bot_alias_tags,
            bot_type: self.bot_type,
            bot_members: self.bot_members,
            error_log_settings: self.error_log_settings,
            _request_id: self._request_id,
        }
    }
}
