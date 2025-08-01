// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this parameter to configure your OIDC Identity Provider (IdP).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct OidcConfig {
    /// <p>The OIDC IdP client ID used to configure your private workforce.</p>
    pub client_id: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP client secret used to configure your private workforce.</p>
    pub client_secret: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP issuer used to configure your private workforce.</p>
    pub issuer: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP authorization endpoint used to configure your private workforce.</p>
    pub authorization_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP token endpoint used to configure your private workforce.</p>
    pub token_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP user information endpoint used to configure your private workforce.</p>
    pub user_info_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP logout endpoint used to configure your private workforce.</p>
    pub logout_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.</p>
    pub jwks_uri: ::std::option::Option<::std::string::String>,
    /// <p>An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.</p>
    pub scope: ::std::option::Option<::std::string::String>,
    /// <p>A string to string map of identifiers specific to the custom identity provider (IdP) being used.</p>
    pub authentication_request_extra_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl OidcConfig {
    /// <p>The OIDC IdP client ID used to configure your private workforce.</p>
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }
    /// <p>The OIDC IdP client secret used to configure your private workforce.</p>
    pub fn client_secret(&self) -> ::std::option::Option<&str> {
        self.client_secret.as_deref()
    }
    /// <p>The OIDC IdP issuer used to configure your private workforce.</p>
    pub fn issuer(&self) -> ::std::option::Option<&str> {
        self.issuer.as_deref()
    }
    /// <p>The OIDC IdP authorization endpoint used to configure your private workforce.</p>
    pub fn authorization_endpoint(&self) -> ::std::option::Option<&str> {
        self.authorization_endpoint.as_deref()
    }
    /// <p>The OIDC IdP token endpoint used to configure your private workforce.</p>
    pub fn token_endpoint(&self) -> ::std::option::Option<&str> {
        self.token_endpoint.as_deref()
    }
    /// <p>The OIDC IdP user information endpoint used to configure your private workforce.</p>
    pub fn user_info_endpoint(&self) -> ::std::option::Option<&str> {
        self.user_info_endpoint.as_deref()
    }
    /// <p>The OIDC IdP logout endpoint used to configure your private workforce.</p>
    pub fn logout_endpoint(&self) -> ::std::option::Option<&str> {
        self.logout_endpoint.as_deref()
    }
    /// <p>The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.</p>
    pub fn jwks_uri(&self) -> ::std::option::Option<&str> {
        self.jwks_uri.as_deref()
    }
    /// <p>An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.</p>
    pub fn scope(&self) -> ::std::option::Option<&str> {
        self.scope.as_deref()
    }
    /// <p>A string to string map of identifiers specific to the custom identity provider (IdP) being used.</p>
    pub fn authentication_request_extra_params(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.authentication_request_extra_params.as_ref()
    }
}
impl ::std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OidcConfig");
        formatter.field("client_id", &self.client_id);
        formatter.field("client_secret", &"*** Sensitive Data Redacted ***");
        formatter.field("issuer", &self.issuer);
        formatter.field("authorization_endpoint", &self.authorization_endpoint);
        formatter.field("token_endpoint", &self.token_endpoint);
        formatter.field("user_info_endpoint", &self.user_info_endpoint);
        formatter.field("logout_endpoint", &self.logout_endpoint);
        formatter.field("jwks_uri", &self.jwks_uri);
        formatter.field("scope", &self.scope);
        formatter.field("authentication_request_extra_params", &self.authentication_request_extra_params);
        formatter.finish()
    }
}
impl OidcConfig {
    /// Creates a new builder-style object to manufacture [`OidcConfig`](crate::types::OidcConfig).
    pub fn builder() -> crate::types::builders::OidcConfigBuilder {
        crate::types::builders::OidcConfigBuilder::default()
    }
}

/// A builder for [`OidcConfig`](crate::types::OidcConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct OidcConfigBuilder {
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_secret: ::std::option::Option<::std::string::String>,
    pub(crate) issuer: ::std::option::Option<::std::string::String>,
    pub(crate) authorization_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) token_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) user_info_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) logout_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) jwks_uri: ::std::option::Option<::std::string::String>,
    pub(crate) scope: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_request_extra_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl OidcConfigBuilder {
    /// <p>The OIDC IdP client ID used to configure your private workforce.</p>
    /// This field is required.
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP client ID used to configure your private workforce.</p>
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }
    /// <p>The OIDC IdP client ID used to configure your private workforce.</p>
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }
    /// <p>The OIDC IdP client secret used to configure your private workforce.</p>
    /// This field is required.
    pub fn client_secret(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_secret = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP client secret used to configure your private workforce.</p>
    pub fn set_client_secret(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_secret = input;
        self
    }
    /// <p>The OIDC IdP client secret used to configure your private workforce.</p>
    pub fn get_client_secret(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_secret
    }
    /// <p>The OIDC IdP issuer used to configure your private workforce.</p>
    /// This field is required.
    pub fn issuer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.issuer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP issuer used to configure your private workforce.</p>
    pub fn set_issuer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.issuer = input;
        self
    }
    /// <p>The OIDC IdP issuer used to configure your private workforce.</p>
    pub fn get_issuer(&self) -> &::std::option::Option<::std::string::String> {
        &self.issuer
    }
    /// <p>The OIDC IdP authorization endpoint used to configure your private workforce.</p>
    /// This field is required.
    pub fn authorization_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorization_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP authorization endpoint used to configure your private workforce.</p>
    pub fn set_authorization_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorization_endpoint = input;
        self
    }
    /// <p>The OIDC IdP authorization endpoint used to configure your private workforce.</p>
    pub fn get_authorization_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorization_endpoint
    }
    /// <p>The OIDC IdP token endpoint used to configure your private workforce.</p>
    /// This field is required.
    pub fn token_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP token endpoint used to configure your private workforce.</p>
    pub fn set_token_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_endpoint = input;
        self
    }
    /// <p>The OIDC IdP token endpoint used to configure your private workforce.</p>
    pub fn get_token_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_endpoint
    }
    /// <p>The OIDC IdP user information endpoint used to configure your private workforce.</p>
    /// This field is required.
    pub fn user_info_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_info_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP user information endpoint used to configure your private workforce.</p>
    pub fn set_user_info_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_info_endpoint = input;
        self
    }
    /// <p>The OIDC IdP user information endpoint used to configure your private workforce.</p>
    pub fn get_user_info_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_info_endpoint
    }
    /// <p>The OIDC IdP logout endpoint used to configure your private workforce.</p>
    /// This field is required.
    pub fn logout_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.logout_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP logout endpoint used to configure your private workforce.</p>
    pub fn set_logout_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.logout_endpoint = input;
        self
    }
    /// <p>The OIDC IdP logout endpoint used to configure your private workforce.</p>
    pub fn get_logout_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.logout_endpoint
    }
    /// <p>The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.</p>
    /// This field is required.
    pub fn jwks_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.jwks_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.</p>
    pub fn set_jwks_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.jwks_uri = input;
        self
    }
    /// <p>The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.</p>
    pub fn get_jwks_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.jwks_uri
    }
    /// <p>An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.</p>
    pub fn scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope = input;
        self
    }
    /// <p>An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.</p>
    pub fn get_scope(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope
    }
    /// Adds a key-value pair to `authentication_request_extra_params`.
    ///
    /// To override the contents of this collection use [`set_authentication_request_extra_params`](Self::set_authentication_request_extra_params).
    ///
    /// <p>A string to string map of identifiers specific to the custom identity provider (IdP) being used.</p>
    pub fn authentication_request_extra_params(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.authentication_request_extra_params.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.authentication_request_extra_params = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A string to string map of identifiers specific to the custom identity provider (IdP) being used.</p>
    pub fn set_authentication_request_extra_params(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.authentication_request_extra_params = input;
        self
    }
    /// <p>A string to string map of identifiers specific to the custom identity provider (IdP) being used.</p>
    pub fn get_authentication_request_extra_params(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.authentication_request_extra_params
    }
    /// Consumes the builder and constructs a [`OidcConfig`](crate::types::OidcConfig).
    pub fn build(self) -> crate::types::OidcConfig {
        crate::types::OidcConfig {
            client_id: self.client_id,
            client_secret: self.client_secret,
            issuer: self.issuer,
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            user_info_endpoint: self.user_info_endpoint,
            logout_endpoint: self.logout_endpoint,
            jwks_uri: self.jwks_uri,
            scope: self.scope,
            authentication_request_extra_params: self.authentication_request_extra_params,
        }
    }
}
impl ::std::fmt::Debug for OidcConfigBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OidcConfigBuilder");
        formatter.field("client_id", &self.client_id);
        formatter.field("client_secret", &"*** Sensitive Data Redacted ***");
        formatter.field("issuer", &self.issuer);
        formatter.field("authorization_endpoint", &self.authorization_endpoint);
        formatter.field("token_endpoint", &self.token_endpoint);
        formatter.field("user_info_endpoint", &self.user_info_endpoint);
        formatter.field("logout_endpoint", &self.logout_endpoint);
        formatter.field("jwks_uri", &self.jwks_uri);
        formatter.field("scope", &self.scope);
        formatter.field("authentication_request_extra_params", &self.authentication_request_extra_params);
        formatter.finish()
    }
}
