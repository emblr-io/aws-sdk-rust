// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the SAML application configured for the domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SamlOptionsOutput {
    /// <p>True if SAML is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>Describes the SAML identity provider's information.</p>
    pub idp: ::std::option::Option<crate::types::SamlIdp>,
    /// <p>The key used for matching the SAML subject attribute.</p>
    pub subject_key: ::std::option::Option<::std::string::String>,
    /// <p>The key used for matching the SAML roles attribute.</p>
    pub roles_key: ::std::option::Option<::std::string::String>,
    /// <p>The duration, in minutes, after which a user session becomes inactive.</p>
    pub session_timeout_minutes: ::std::option::Option<i32>,
}
impl SamlOptionsOutput {
    /// <p>True if SAML is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>Describes the SAML identity provider's information.</p>
    pub fn idp(&self) -> ::std::option::Option<&crate::types::SamlIdp> {
        self.idp.as_ref()
    }
    /// <p>The key used for matching the SAML subject attribute.</p>
    pub fn subject_key(&self) -> ::std::option::Option<&str> {
        self.subject_key.as_deref()
    }
    /// <p>The key used for matching the SAML roles attribute.</p>
    pub fn roles_key(&self) -> ::std::option::Option<&str> {
        self.roles_key.as_deref()
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive.</p>
    pub fn session_timeout_minutes(&self) -> ::std::option::Option<i32> {
        self.session_timeout_minutes
    }
}
impl SamlOptionsOutput {
    /// Creates a new builder-style object to manufacture [`SamlOptionsOutput`](crate::types::SamlOptionsOutput).
    pub fn builder() -> crate::types::builders::SamlOptionsOutputBuilder {
        crate::types::builders::SamlOptionsOutputBuilder::default()
    }
}

/// A builder for [`SamlOptionsOutput`](crate::types::SamlOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SamlOptionsOutputBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) idp: ::std::option::Option<crate::types::SamlIdp>,
    pub(crate) subject_key: ::std::option::Option<::std::string::String>,
    pub(crate) roles_key: ::std::option::Option<::std::string::String>,
    pub(crate) session_timeout_minutes: ::std::option::Option<i32>,
}
impl SamlOptionsOutputBuilder {
    /// <p>True if SAML is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if SAML is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>True if SAML is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>Describes the SAML identity provider's information.</p>
    pub fn idp(mut self, input: crate::types::SamlIdp) -> Self {
        self.idp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the SAML identity provider's information.</p>
    pub fn set_idp(mut self, input: ::std::option::Option<crate::types::SamlIdp>) -> Self {
        self.idp = input;
        self
    }
    /// <p>Describes the SAML identity provider's information.</p>
    pub fn get_idp(&self) -> &::std::option::Option<crate::types::SamlIdp> {
        &self.idp
    }
    /// <p>The key used for matching the SAML subject attribute.</p>
    pub fn subject_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key used for matching the SAML subject attribute.</p>
    pub fn set_subject_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_key = input;
        self
    }
    /// <p>The key used for matching the SAML subject attribute.</p>
    pub fn get_subject_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_key
    }
    /// <p>The key used for matching the SAML roles attribute.</p>
    pub fn roles_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.roles_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key used for matching the SAML roles attribute.</p>
    pub fn set_roles_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.roles_key = input;
        self
    }
    /// <p>The key used for matching the SAML roles attribute.</p>
    pub fn get_roles_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.roles_key
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive.</p>
    pub fn session_timeout_minutes(mut self, input: i32) -> Self {
        self.session_timeout_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive.</p>
    pub fn set_session_timeout_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.session_timeout_minutes = input;
        self
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive.</p>
    pub fn get_session_timeout_minutes(&self) -> &::std::option::Option<i32> {
        &self.session_timeout_minutes
    }
    /// Consumes the builder and constructs a [`SamlOptionsOutput`](crate::types::SamlOptionsOutput).
    pub fn build(self) -> crate::types::SamlOptionsOutput {
        crate::types::SamlOptionsOutput {
            enabled: self.enabled,
            idp: self.idp,
            subject_key: self.subject_key,
            roles_key: self.roles_key,
            session_timeout_minutes: self.session_timeout_minutes,
        }
    }
}
