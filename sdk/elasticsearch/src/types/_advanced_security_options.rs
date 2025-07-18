// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the advanced security configuration: whether advanced security is enabled, whether the internal database option is enabled.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AdvancedSecurityOptions {
    /// <p>True if advanced security is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>True if the internal user database is enabled.</p>
    pub internal_user_database_enabled: ::std::option::Option<bool>,
    /// <p>Describes the SAML application configured for a domain.</p>
    pub saml_options: ::std::option::Option<crate::types::SamlOptionsOutput>,
    /// <p>Specifies the Anonymous Auth Disable Date when Anonymous Auth is enabled.</p>
    pub anonymous_auth_disable_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>True if Anonymous auth is enabled. Anonymous auth can be enabled only when AdvancedSecurity is enabled on existing domains.</p>
    pub anonymous_auth_enabled: ::std::option::Option<bool>,
}
impl AdvancedSecurityOptions {
    /// <p>True if advanced security is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>True if the internal user database is enabled.</p>
    pub fn internal_user_database_enabled(&self) -> ::std::option::Option<bool> {
        self.internal_user_database_enabled
    }
    /// <p>Describes the SAML application configured for a domain.</p>
    pub fn saml_options(&self) -> ::std::option::Option<&crate::types::SamlOptionsOutput> {
        self.saml_options.as_ref()
    }
    /// <p>Specifies the Anonymous Auth Disable Date when Anonymous Auth is enabled.</p>
    pub fn anonymous_auth_disable_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.anonymous_auth_disable_date.as_ref()
    }
    /// <p>True if Anonymous auth is enabled. Anonymous auth can be enabled only when AdvancedSecurity is enabled on existing domains.</p>
    pub fn anonymous_auth_enabled(&self) -> ::std::option::Option<bool> {
        self.anonymous_auth_enabled
    }
}
impl AdvancedSecurityOptions {
    /// Creates a new builder-style object to manufacture [`AdvancedSecurityOptions`](crate::types::AdvancedSecurityOptions).
    pub fn builder() -> crate::types::builders::AdvancedSecurityOptionsBuilder {
        crate::types::builders::AdvancedSecurityOptionsBuilder::default()
    }
}

/// A builder for [`AdvancedSecurityOptions`](crate::types::AdvancedSecurityOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AdvancedSecurityOptionsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) internal_user_database_enabled: ::std::option::Option<bool>,
    pub(crate) saml_options: ::std::option::Option<crate::types::SamlOptionsOutput>,
    pub(crate) anonymous_auth_disable_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) anonymous_auth_enabled: ::std::option::Option<bool>,
}
impl AdvancedSecurityOptionsBuilder {
    /// <p>True if advanced security is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if advanced security is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>True if advanced security is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>True if the internal user database is enabled.</p>
    pub fn internal_user_database_enabled(mut self, input: bool) -> Self {
        self.internal_user_database_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if the internal user database is enabled.</p>
    pub fn set_internal_user_database_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.internal_user_database_enabled = input;
        self
    }
    /// <p>True if the internal user database is enabled.</p>
    pub fn get_internal_user_database_enabled(&self) -> &::std::option::Option<bool> {
        &self.internal_user_database_enabled
    }
    /// <p>Describes the SAML application configured for a domain.</p>
    pub fn saml_options(mut self, input: crate::types::SamlOptionsOutput) -> Self {
        self.saml_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the SAML application configured for a domain.</p>
    pub fn set_saml_options(mut self, input: ::std::option::Option<crate::types::SamlOptionsOutput>) -> Self {
        self.saml_options = input;
        self
    }
    /// <p>Describes the SAML application configured for a domain.</p>
    pub fn get_saml_options(&self) -> &::std::option::Option<crate::types::SamlOptionsOutput> {
        &self.saml_options
    }
    /// <p>Specifies the Anonymous Auth Disable Date when Anonymous Auth is enabled.</p>
    pub fn anonymous_auth_disable_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.anonymous_auth_disable_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Anonymous Auth Disable Date when Anonymous Auth is enabled.</p>
    pub fn set_anonymous_auth_disable_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.anonymous_auth_disable_date = input;
        self
    }
    /// <p>Specifies the Anonymous Auth Disable Date when Anonymous Auth is enabled.</p>
    pub fn get_anonymous_auth_disable_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.anonymous_auth_disable_date
    }
    /// <p>True if Anonymous auth is enabled. Anonymous auth can be enabled only when AdvancedSecurity is enabled on existing domains.</p>
    pub fn anonymous_auth_enabled(mut self, input: bool) -> Self {
        self.anonymous_auth_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if Anonymous auth is enabled. Anonymous auth can be enabled only when AdvancedSecurity is enabled on existing domains.</p>
    pub fn set_anonymous_auth_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.anonymous_auth_enabled = input;
        self
    }
    /// <p>True if Anonymous auth is enabled. Anonymous auth can be enabled only when AdvancedSecurity is enabled on existing domains.</p>
    pub fn get_anonymous_auth_enabled(&self) -> &::std::option::Option<bool> {
        &self.anonymous_auth_enabled
    }
    /// Consumes the builder and constructs a [`AdvancedSecurityOptions`](crate::types::AdvancedSecurityOptions).
    pub fn build(self) -> crate::types::AdvancedSecurityOptions {
        crate::types::AdvancedSecurityOptions {
            enabled: self.enabled,
            internal_user_database_enabled: self.internal_user_database_enabled,
            saml_options: self.saml_options,
            anonymous_auth_disable_date: self.anonymous_auth_disable_date,
            anonymous_auth_enabled: self.anonymous_auth_enabled,
        }
    }
}
