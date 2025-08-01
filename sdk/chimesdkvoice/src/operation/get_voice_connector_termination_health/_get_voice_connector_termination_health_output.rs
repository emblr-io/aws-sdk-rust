// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVoiceConnectorTerminationHealthOutput {
    /// <p>The termination health details.</p>
    pub termination_health: ::std::option::Option<crate::types::TerminationHealth>,
    _request_id: Option<String>,
}
impl GetVoiceConnectorTerminationHealthOutput {
    /// <p>The termination health details.</p>
    pub fn termination_health(&self) -> ::std::option::Option<&crate::types::TerminationHealth> {
        self.termination_health.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetVoiceConnectorTerminationHealthOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetVoiceConnectorTerminationHealthOutput {
    /// Creates a new builder-style object to manufacture [`GetVoiceConnectorTerminationHealthOutput`](crate::operation::get_voice_connector_termination_health::GetVoiceConnectorTerminationHealthOutput).
    pub fn builder() -> crate::operation::get_voice_connector_termination_health::builders::GetVoiceConnectorTerminationHealthOutputBuilder {
        crate::operation::get_voice_connector_termination_health::builders::GetVoiceConnectorTerminationHealthOutputBuilder::default()
    }
}

/// A builder for [`GetVoiceConnectorTerminationHealthOutput`](crate::operation::get_voice_connector_termination_health::GetVoiceConnectorTerminationHealthOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVoiceConnectorTerminationHealthOutputBuilder {
    pub(crate) termination_health: ::std::option::Option<crate::types::TerminationHealth>,
    _request_id: Option<String>,
}
impl GetVoiceConnectorTerminationHealthOutputBuilder {
    /// <p>The termination health details.</p>
    pub fn termination_health(mut self, input: crate::types::TerminationHealth) -> Self {
        self.termination_health = ::std::option::Option::Some(input);
        self
    }
    /// <p>The termination health details.</p>
    pub fn set_termination_health(mut self, input: ::std::option::Option<crate::types::TerminationHealth>) -> Self {
        self.termination_health = input;
        self
    }
    /// <p>The termination health details.</p>
    pub fn get_termination_health(&self) -> &::std::option::Option<crate::types::TerminationHealth> {
        &self.termination_health
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetVoiceConnectorTerminationHealthOutput`](crate::operation::get_voice_connector_termination_health::GetVoiceConnectorTerminationHealthOutput).
    pub fn build(self) -> crate::operation::get_voice_connector_termination_health::GetVoiceConnectorTerminationHealthOutput {
        crate::operation::get_voice_connector_termination_health::GetVoiceConnectorTerminationHealthOutput {
            termination_health: self.termination_health,
            _request_id: self._request_id,
        }
    }
}
