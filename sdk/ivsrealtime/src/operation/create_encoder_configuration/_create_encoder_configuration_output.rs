// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEncoderConfigurationOutput {
    /// <p>The EncoderConfiguration that was created.</p>
    pub encoder_configuration: ::std::option::Option<crate::types::EncoderConfiguration>,
    _request_id: Option<String>,
}
impl CreateEncoderConfigurationOutput {
    /// <p>The EncoderConfiguration that was created.</p>
    pub fn encoder_configuration(&self) -> ::std::option::Option<&crate::types::EncoderConfiguration> {
        self.encoder_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEncoderConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEncoderConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`CreateEncoderConfigurationOutput`](crate::operation::create_encoder_configuration::CreateEncoderConfigurationOutput).
    pub fn builder() -> crate::operation::create_encoder_configuration::builders::CreateEncoderConfigurationOutputBuilder {
        crate::operation::create_encoder_configuration::builders::CreateEncoderConfigurationOutputBuilder::default()
    }
}

/// A builder for [`CreateEncoderConfigurationOutput`](crate::operation::create_encoder_configuration::CreateEncoderConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEncoderConfigurationOutputBuilder {
    pub(crate) encoder_configuration: ::std::option::Option<crate::types::EncoderConfiguration>,
    _request_id: Option<String>,
}
impl CreateEncoderConfigurationOutputBuilder {
    /// <p>The EncoderConfiguration that was created.</p>
    pub fn encoder_configuration(mut self, input: crate::types::EncoderConfiguration) -> Self {
        self.encoder_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The EncoderConfiguration that was created.</p>
    pub fn set_encoder_configuration(mut self, input: ::std::option::Option<crate::types::EncoderConfiguration>) -> Self {
        self.encoder_configuration = input;
        self
    }
    /// <p>The EncoderConfiguration that was created.</p>
    pub fn get_encoder_configuration(&self) -> &::std::option::Option<crate::types::EncoderConfiguration> {
        &self.encoder_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEncoderConfigurationOutput`](crate::operation::create_encoder_configuration::CreateEncoderConfigurationOutput).
    pub fn build(self) -> crate::operation::create_encoder_configuration::CreateEncoderConfigurationOutput {
        crate::operation::create_encoder_configuration::CreateEncoderConfigurationOutput {
            encoder_configuration: self.encoder_configuration,
            _request_id: self._request_id,
        }
    }
}
