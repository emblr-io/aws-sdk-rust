// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVoiceConnectorLoggingConfigurationInput {
    /// <p>The Voice Connector ID.</p>
    pub voice_connector_id: ::std::option::Option<::std::string::String>,
}
impl GetVoiceConnectorLoggingConfigurationInput {
    /// <p>The Voice Connector ID.</p>
    pub fn voice_connector_id(&self) -> ::std::option::Option<&str> {
        self.voice_connector_id.as_deref()
    }
}
impl GetVoiceConnectorLoggingConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetVoiceConnectorLoggingConfigurationInput`](crate::operation::get_voice_connector_logging_configuration::GetVoiceConnectorLoggingConfigurationInput).
    pub fn builder() -> crate::operation::get_voice_connector_logging_configuration::builders::GetVoiceConnectorLoggingConfigurationInputBuilder {
        crate::operation::get_voice_connector_logging_configuration::builders::GetVoiceConnectorLoggingConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetVoiceConnectorLoggingConfigurationInput`](crate::operation::get_voice_connector_logging_configuration::GetVoiceConnectorLoggingConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVoiceConnectorLoggingConfigurationInputBuilder {
    pub(crate) voice_connector_id: ::std::option::Option<::std::string::String>,
}
impl GetVoiceConnectorLoggingConfigurationInputBuilder {
    /// <p>The Voice Connector ID.</p>
    /// This field is required.
    pub fn voice_connector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.voice_connector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Voice Connector ID.</p>
    pub fn set_voice_connector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.voice_connector_id = input;
        self
    }
    /// <p>The Voice Connector ID.</p>
    pub fn get_voice_connector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.voice_connector_id
    }
    /// Consumes the builder and constructs a [`GetVoiceConnectorLoggingConfigurationInput`](crate::operation::get_voice_connector_logging_configuration::GetVoiceConnectorLoggingConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_voice_connector_logging_configuration::GetVoiceConnectorLoggingConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_voice_connector_logging_configuration::GetVoiceConnectorLoggingConfigurationInput {
                voice_connector_id: self.voice_connector_id,
            },
        )
    }
}
