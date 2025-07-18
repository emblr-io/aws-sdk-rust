// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutHubConfigurationOutput {
    /// <p>A user-defined integer value that represents the hub token timer expiry setting in seconds.</p>
    pub hub_token_timer_expiry_setting_in_seconds: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl PutHubConfigurationOutput {
    /// <p>A user-defined integer value that represents the hub token timer expiry setting in seconds.</p>
    pub fn hub_token_timer_expiry_setting_in_seconds(&self) -> ::std::option::Option<i64> {
        self.hub_token_timer_expiry_setting_in_seconds
    }
}
impl ::aws_types::request_id::RequestId for PutHubConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutHubConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutHubConfigurationOutput`](crate::operation::put_hub_configuration::PutHubConfigurationOutput).
    pub fn builder() -> crate::operation::put_hub_configuration::builders::PutHubConfigurationOutputBuilder {
        crate::operation::put_hub_configuration::builders::PutHubConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutHubConfigurationOutput`](crate::operation::put_hub_configuration::PutHubConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutHubConfigurationOutputBuilder {
    pub(crate) hub_token_timer_expiry_setting_in_seconds: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl PutHubConfigurationOutputBuilder {
    /// <p>A user-defined integer value that represents the hub token timer expiry setting in seconds.</p>
    pub fn hub_token_timer_expiry_setting_in_seconds(mut self, input: i64) -> Self {
        self.hub_token_timer_expiry_setting_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>A user-defined integer value that represents the hub token timer expiry setting in seconds.</p>
    pub fn set_hub_token_timer_expiry_setting_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.hub_token_timer_expiry_setting_in_seconds = input;
        self
    }
    /// <p>A user-defined integer value that represents the hub token timer expiry setting in seconds.</p>
    pub fn get_hub_token_timer_expiry_setting_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.hub_token_timer_expiry_setting_in_seconds
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutHubConfigurationOutput`](crate::operation::put_hub_configuration::PutHubConfigurationOutput).
    pub fn build(self) -> crate::operation::put_hub_configuration::PutHubConfigurationOutput {
        crate::operation::put_hub_configuration::PutHubConfigurationOutput {
            hub_token_timer_expiry_setting_in_seconds: self.hub_token_timer_expiry_setting_in_seconds,
            _request_id: self._request_id,
        }
    }
}
