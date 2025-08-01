// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSlackChannelConfigurationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for CreateSlackChannelConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSlackChannelConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`CreateSlackChannelConfigurationOutput`](crate::operation::create_slack_channel_configuration::CreateSlackChannelConfigurationOutput).
    pub fn builder() -> crate::operation::create_slack_channel_configuration::builders::CreateSlackChannelConfigurationOutputBuilder {
        crate::operation::create_slack_channel_configuration::builders::CreateSlackChannelConfigurationOutputBuilder::default()
    }
}

/// A builder for [`CreateSlackChannelConfigurationOutput`](crate::operation::create_slack_channel_configuration::CreateSlackChannelConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSlackChannelConfigurationOutputBuilder {
    _request_id: Option<String>,
}
impl CreateSlackChannelConfigurationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSlackChannelConfigurationOutput`](crate::operation::create_slack_channel_configuration::CreateSlackChannelConfigurationOutput).
    pub fn build(self) -> crate::operation::create_slack_channel_configuration::CreateSlackChannelConfigurationOutput {
        crate::operation::create_slack_channel_configuration::CreateSlackChannelConfigurationOutput {
            _request_id: self._request_id,
        }
    }
}
