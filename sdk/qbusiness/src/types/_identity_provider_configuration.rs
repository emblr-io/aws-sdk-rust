// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum IdentityProviderConfiguration {
    /// <p>Information about the OIDC-compliant identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    OpenIdConnectConfiguration(crate::types::OpenIdConnectProviderConfiguration),
    /// <p>Information about the SAML 2.0-compliant identity provider (IdP) used to authenticate end users of an Amazon Q Business web experience.</p>
    SamlConfiguration(crate::types::SamlProviderConfiguration),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl IdentityProviderConfiguration {
    /// Tries to convert the enum instance into [`OpenIdConnectConfiguration`](crate::types::IdentityProviderConfiguration::OpenIdConnectConfiguration), extracting the inner [`OpenIdConnectProviderConfiguration`](crate::types::OpenIdConnectProviderConfiguration).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_open_id_connect_configuration(&self) -> ::std::result::Result<&crate::types::OpenIdConnectProviderConfiguration, &Self> {
        if let IdentityProviderConfiguration::OpenIdConnectConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`OpenIdConnectConfiguration`](crate::types::IdentityProviderConfiguration::OpenIdConnectConfiguration).
    pub fn is_open_id_connect_configuration(&self) -> bool {
        self.as_open_id_connect_configuration().is_ok()
    }
    /// Tries to convert the enum instance into [`SamlConfiguration`](crate::types::IdentityProviderConfiguration::SamlConfiguration), extracting the inner [`SamlProviderConfiguration`](crate::types::SamlProviderConfiguration).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_saml_configuration(&self) -> ::std::result::Result<&crate::types::SamlProviderConfiguration, &Self> {
        if let IdentityProviderConfiguration::SamlConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`SamlConfiguration`](crate::types::IdentityProviderConfiguration::SamlConfiguration).
    pub fn is_saml_configuration(&self) -> bool {
        self.as_saml_configuration().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
