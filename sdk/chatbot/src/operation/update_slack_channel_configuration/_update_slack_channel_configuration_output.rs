// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSlackChannelConfigurationOutput {
    /// <p>The configuration for a Slack channel configured with AWS Chatbot.</p>
    pub channel_configuration: ::std::option::Option<crate::types::SlackChannelConfiguration>,
    _request_id: Option<String>,
}
impl UpdateSlackChannelConfigurationOutput {
    /// <p>The configuration for a Slack channel configured with AWS Chatbot.</p>
    pub fn channel_configuration(&self) -> ::std::option::Option<&crate::types::SlackChannelConfiguration> {
        self.channel_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSlackChannelConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSlackChannelConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSlackChannelConfigurationOutput`](crate::operation::update_slack_channel_configuration::UpdateSlackChannelConfigurationOutput).
    pub fn builder() -> crate::operation::update_slack_channel_configuration::builders::UpdateSlackChannelConfigurationOutputBuilder {
        crate::operation::update_slack_channel_configuration::builders::UpdateSlackChannelConfigurationOutputBuilder::default()
    }
}

/// A builder for [`UpdateSlackChannelConfigurationOutput`](crate::operation::update_slack_channel_configuration::UpdateSlackChannelConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSlackChannelConfigurationOutputBuilder {
    pub(crate) channel_configuration: ::std::option::Option<crate::types::SlackChannelConfiguration>,
    _request_id: Option<String>,
}
impl UpdateSlackChannelConfigurationOutputBuilder {
    /// <p>The configuration for a Slack channel configured with AWS Chatbot.</p>
    pub fn channel_configuration(mut self, input: crate::types::SlackChannelConfiguration) -> Self {
        self.channel_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for a Slack channel configured with AWS Chatbot.</p>
    pub fn set_channel_configuration(mut self, input: ::std::option::Option<crate::types::SlackChannelConfiguration>) -> Self {
        self.channel_configuration = input;
        self
    }
    /// <p>The configuration for a Slack channel configured with AWS Chatbot.</p>
    pub fn get_channel_configuration(&self) -> &::std::option::Option<crate::types::SlackChannelConfiguration> {
        &self.channel_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateSlackChannelConfigurationOutput`](crate::operation::update_slack_channel_configuration::UpdateSlackChannelConfigurationOutput).
    pub fn build(self) -> crate::operation::update_slack_channel_configuration::UpdateSlackChannelConfigurationOutput {
        crate::operation::update_slack_channel_configuration::UpdateSlackChannelConfigurationOutput {
            channel_configuration: self.channel_configuration,
            _request_id: self._request_id,
        }
    }
}
