// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeIdentityProviderConfigurationOutput {
    /// <p>The authentication mode used in WorkMail.</p>
    pub authentication_mode: ::std::option::Option<crate::types::IdentityProviderAuthenticationMode>,
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    /// <p>The details of the Personal Access Token configuration.</p>
    pub personal_access_token_configuration: ::std::option::Option<crate::types::PersonalAccessTokenConfiguration>,
    _request_id: Option<String>,
}
impl DescribeIdentityProviderConfigurationOutput {
    /// <p>The authentication mode used in WorkMail.</p>
    pub fn authentication_mode(&self) -> ::std::option::Option<&crate::types::IdentityProviderAuthenticationMode> {
        self.authentication_mode.as_ref()
    }
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub fn identity_center_configuration(&self) -> ::std::option::Option<&crate::types::IdentityCenterConfiguration> {
        self.identity_center_configuration.as_ref()
    }
    /// <p>The details of the Personal Access Token configuration.</p>
    pub fn personal_access_token_configuration(&self) -> ::std::option::Option<&crate::types::PersonalAccessTokenConfiguration> {
        self.personal_access_token_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeIdentityProviderConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeIdentityProviderConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeIdentityProviderConfigurationOutput`](crate::operation::describe_identity_provider_configuration::DescribeIdentityProviderConfigurationOutput).
    pub fn builder() -> crate::operation::describe_identity_provider_configuration::builders::DescribeIdentityProviderConfigurationOutputBuilder {
        crate::operation::describe_identity_provider_configuration::builders::DescribeIdentityProviderConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeIdentityProviderConfigurationOutput`](crate::operation::describe_identity_provider_configuration::DescribeIdentityProviderConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeIdentityProviderConfigurationOutputBuilder {
    pub(crate) authentication_mode: ::std::option::Option<crate::types::IdentityProviderAuthenticationMode>,
    pub(crate) identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    pub(crate) personal_access_token_configuration: ::std::option::Option<crate::types::PersonalAccessTokenConfiguration>,
    _request_id: Option<String>,
}
impl DescribeIdentityProviderConfigurationOutputBuilder {
    /// <p>The authentication mode used in WorkMail.</p>
    pub fn authentication_mode(mut self, input: crate::types::IdentityProviderAuthenticationMode) -> Self {
        self.authentication_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authentication mode used in WorkMail.</p>
    pub fn set_authentication_mode(mut self, input: ::std::option::Option<crate::types::IdentityProviderAuthenticationMode>) -> Self {
        self.authentication_mode = input;
        self
    }
    /// <p>The authentication mode used in WorkMail.</p>
    pub fn get_authentication_mode(&self) -> &::std::option::Option<crate::types::IdentityProviderAuthenticationMode> {
        &self.authentication_mode
    }
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub fn identity_center_configuration(mut self, input: crate::types::IdentityCenterConfiguration) -> Self {
        self.identity_center_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub fn set_identity_center_configuration(mut self, input: ::std::option::Option<crate::types::IdentityCenterConfiguration>) -> Self {
        self.identity_center_configuration = input;
        self
    }
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub fn get_identity_center_configuration(&self) -> &::std::option::Option<crate::types::IdentityCenterConfiguration> {
        &self.identity_center_configuration
    }
    /// <p>The details of the Personal Access Token configuration.</p>
    pub fn personal_access_token_configuration(mut self, input: crate::types::PersonalAccessTokenConfiguration) -> Self {
        self.personal_access_token_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the Personal Access Token configuration.</p>
    pub fn set_personal_access_token_configuration(mut self, input: ::std::option::Option<crate::types::PersonalAccessTokenConfiguration>) -> Self {
        self.personal_access_token_configuration = input;
        self
    }
    /// <p>The details of the Personal Access Token configuration.</p>
    pub fn get_personal_access_token_configuration(&self) -> &::std::option::Option<crate::types::PersonalAccessTokenConfiguration> {
        &self.personal_access_token_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeIdentityProviderConfigurationOutput`](crate::operation::describe_identity_provider_configuration::DescribeIdentityProviderConfigurationOutput).
    pub fn build(self) -> crate::operation::describe_identity_provider_configuration::DescribeIdentityProviderConfigurationOutput {
        crate::operation::describe_identity_provider_configuration::DescribeIdentityProviderConfigurationOutput {
            authentication_mode: self.authentication_mode,
            identity_center_configuration: self.identity_center_configuration,
            personal_access_token_configuration: self.personal_access_token_configuration,
            _request_id: self._request_id,
        }
    }
}
