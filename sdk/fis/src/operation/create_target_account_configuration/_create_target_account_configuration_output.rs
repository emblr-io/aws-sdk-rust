// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTargetAccountConfigurationOutput {
    /// <p>Information about the target account configuration.</p>
    pub target_account_configuration: ::std::option::Option<crate::types::TargetAccountConfiguration>,
    _request_id: Option<String>,
}
impl CreateTargetAccountConfigurationOutput {
    /// <p>Information about the target account configuration.</p>
    pub fn target_account_configuration(&self) -> ::std::option::Option<&crate::types::TargetAccountConfiguration> {
        self.target_account_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTargetAccountConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTargetAccountConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`CreateTargetAccountConfigurationOutput`](crate::operation::create_target_account_configuration::CreateTargetAccountConfigurationOutput).
    pub fn builder() -> crate::operation::create_target_account_configuration::builders::CreateTargetAccountConfigurationOutputBuilder {
        crate::operation::create_target_account_configuration::builders::CreateTargetAccountConfigurationOutputBuilder::default()
    }
}

/// A builder for [`CreateTargetAccountConfigurationOutput`](crate::operation::create_target_account_configuration::CreateTargetAccountConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTargetAccountConfigurationOutputBuilder {
    pub(crate) target_account_configuration: ::std::option::Option<crate::types::TargetAccountConfiguration>,
    _request_id: Option<String>,
}
impl CreateTargetAccountConfigurationOutputBuilder {
    /// <p>Information about the target account configuration.</p>
    pub fn target_account_configuration(mut self, input: crate::types::TargetAccountConfiguration) -> Self {
        self.target_account_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the target account configuration.</p>
    pub fn set_target_account_configuration(mut self, input: ::std::option::Option<crate::types::TargetAccountConfiguration>) -> Self {
        self.target_account_configuration = input;
        self
    }
    /// <p>Information about the target account configuration.</p>
    pub fn get_target_account_configuration(&self) -> &::std::option::Option<crate::types::TargetAccountConfiguration> {
        &self.target_account_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTargetAccountConfigurationOutput`](crate::operation::create_target_account_configuration::CreateTargetAccountConfigurationOutput).
    pub fn build(self) -> crate::operation::create_target_account_configuration::CreateTargetAccountConfigurationOutput {
        crate::operation::create_target_account_configuration::CreateTargetAccountConfigurationOutput {
            target_account_configuration: self.target_account_configuration,
            _request_id: self._request_id,
        }
    }
}
