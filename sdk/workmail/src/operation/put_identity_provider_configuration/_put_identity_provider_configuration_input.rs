// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutIdentityProviderConfigurationInput {
    /// <p>The ID of the WorkMail Organization.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The authentication mode used in WorkMail.</p>
    pub authentication_mode: ::std::option::Option<crate::types::IdentityProviderAuthenticationMode>,
    /// <p>The details of the IAM Identity Center configuration.</p>
    pub identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    /// <p>The details of the Personal Access Token configuration.</p>
    pub personal_access_token_configuration: ::std::option::Option<crate::types::PersonalAccessTokenConfiguration>,
}
impl PutIdentityProviderConfigurationInput {
    /// <p>The ID of the WorkMail Organization.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
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
impl PutIdentityProviderConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutIdentityProviderConfigurationInput`](crate::operation::put_identity_provider_configuration::PutIdentityProviderConfigurationInput).
    pub fn builder() -> crate::operation::put_identity_provider_configuration::builders::PutIdentityProviderConfigurationInputBuilder {
        crate::operation::put_identity_provider_configuration::builders::PutIdentityProviderConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutIdentityProviderConfigurationInput`](crate::operation::put_identity_provider_configuration::PutIdentityProviderConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutIdentityProviderConfigurationInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_mode: ::std::option::Option<crate::types::IdentityProviderAuthenticationMode>,
    pub(crate) identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    pub(crate) personal_access_token_configuration: ::std::option::Option<crate::types::PersonalAccessTokenConfiguration>,
}
impl PutIdentityProviderConfigurationInputBuilder {
    /// <p>The ID of the WorkMail Organization.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the WorkMail Organization.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The ID of the WorkMail Organization.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The authentication mode used in WorkMail.</p>
    /// This field is required.
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
    /// This field is required.
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
    /// This field is required.
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
    /// Consumes the builder and constructs a [`PutIdentityProviderConfigurationInput`](crate::operation::put_identity_provider_configuration::PutIdentityProviderConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_identity_provider_configuration::PutIdentityProviderConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_identity_provider_configuration::PutIdentityProviderConfigurationInput {
                organization_id: self.organization_id,
                authentication_mode: self.authentication_mode,
                identity_center_configuration: self.identity_center_configuration,
                personal_access_token_configuration: self.personal_access_token_configuration,
            },
        )
    }
}
