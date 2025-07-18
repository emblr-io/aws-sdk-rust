// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure containing properties for OAuth2 in the CreateConnection request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OAuth2PropertiesInput {
    /// <p>The OAuth2 grant type in the CreateConnection request. For example, <code>AUTHORIZATION_CODE</code>, <code>JWT_BEARER</code>, or <code>CLIENT_CREDENTIALS</code>.</p>
    pub o_auth2_grant_type: ::std::option::Option<crate::types::OAuth2GrantType>,
    /// <p>The client application type in the CreateConnection request. For example, <code>AWS_MANAGED</code> or <code>USER_MANAGED</code>.</p>
    pub o_auth2_client_application: ::std::option::Option<crate::types::OAuth2ClientApplication>,
    /// <p>The URL of the provider's authentication server, to exchange an authorization code for an access token.</p>
    pub token_url: ::std::option::Option<::std::string::String>,
    /// <p>A map of parameters that are added to the token <code>GET</code> request.</p>
    pub token_url_parameters_map: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The set of properties required for the the OAuth2 <code>AUTHORIZATION_CODE</code> grant type.</p>
    pub authorization_code_properties: ::std::option::Option<crate::types::AuthorizationCodeProperties>,
    /// <p>The credentials used when the authentication type is OAuth2 authentication.</p>
    pub o_auth2_credentials: ::std::option::Option<crate::types::OAuth2Credentials>,
}
impl OAuth2PropertiesInput {
    /// <p>The OAuth2 grant type in the CreateConnection request. For example, <code>AUTHORIZATION_CODE</code>, <code>JWT_BEARER</code>, or <code>CLIENT_CREDENTIALS</code>.</p>
    pub fn o_auth2_grant_type(&self) -> ::std::option::Option<&crate::types::OAuth2GrantType> {
        self.o_auth2_grant_type.as_ref()
    }
    /// <p>The client application type in the CreateConnection request. For example, <code>AWS_MANAGED</code> or <code>USER_MANAGED</code>.</p>
    pub fn o_auth2_client_application(&self) -> ::std::option::Option<&crate::types::OAuth2ClientApplication> {
        self.o_auth2_client_application.as_ref()
    }
    /// <p>The URL of the provider's authentication server, to exchange an authorization code for an access token.</p>
    pub fn token_url(&self) -> ::std::option::Option<&str> {
        self.token_url.as_deref()
    }
    /// <p>A map of parameters that are added to the token <code>GET</code> request.</p>
    pub fn token_url_parameters_map(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.token_url_parameters_map.as_ref()
    }
    /// <p>The set of properties required for the the OAuth2 <code>AUTHORIZATION_CODE</code> grant type.</p>
    pub fn authorization_code_properties(&self) -> ::std::option::Option<&crate::types::AuthorizationCodeProperties> {
        self.authorization_code_properties.as_ref()
    }
    /// <p>The credentials used when the authentication type is OAuth2 authentication.</p>
    pub fn o_auth2_credentials(&self) -> ::std::option::Option<&crate::types::OAuth2Credentials> {
        self.o_auth2_credentials.as_ref()
    }
}
impl OAuth2PropertiesInput {
    /// Creates a new builder-style object to manufacture [`OAuth2PropertiesInput`](crate::types::OAuth2PropertiesInput).
    pub fn builder() -> crate::types::builders::OAuth2PropertiesInputBuilder {
        crate::types::builders::OAuth2PropertiesInputBuilder::default()
    }
}

/// A builder for [`OAuth2PropertiesInput`](crate::types::OAuth2PropertiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OAuth2PropertiesInputBuilder {
    pub(crate) o_auth2_grant_type: ::std::option::Option<crate::types::OAuth2GrantType>,
    pub(crate) o_auth2_client_application: ::std::option::Option<crate::types::OAuth2ClientApplication>,
    pub(crate) token_url: ::std::option::Option<::std::string::String>,
    pub(crate) token_url_parameters_map: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) authorization_code_properties: ::std::option::Option<crate::types::AuthorizationCodeProperties>,
    pub(crate) o_auth2_credentials: ::std::option::Option<crate::types::OAuth2Credentials>,
}
impl OAuth2PropertiesInputBuilder {
    /// <p>The OAuth2 grant type in the CreateConnection request. For example, <code>AUTHORIZATION_CODE</code>, <code>JWT_BEARER</code>, or <code>CLIENT_CREDENTIALS</code>.</p>
    pub fn o_auth2_grant_type(mut self, input: crate::types::OAuth2GrantType) -> Self {
        self.o_auth2_grant_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OAuth2 grant type in the CreateConnection request. For example, <code>AUTHORIZATION_CODE</code>, <code>JWT_BEARER</code>, or <code>CLIENT_CREDENTIALS</code>.</p>
    pub fn set_o_auth2_grant_type(mut self, input: ::std::option::Option<crate::types::OAuth2GrantType>) -> Self {
        self.o_auth2_grant_type = input;
        self
    }
    /// <p>The OAuth2 grant type in the CreateConnection request. For example, <code>AUTHORIZATION_CODE</code>, <code>JWT_BEARER</code>, or <code>CLIENT_CREDENTIALS</code>.</p>
    pub fn get_o_auth2_grant_type(&self) -> &::std::option::Option<crate::types::OAuth2GrantType> {
        &self.o_auth2_grant_type
    }
    /// <p>The client application type in the CreateConnection request. For example, <code>AWS_MANAGED</code> or <code>USER_MANAGED</code>.</p>
    pub fn o_auth2_client_application(mut self, input: crate::types::OAuth2ClientApplication) -> Self {
        self.o_auth2_client_application = ::std::option::Option::Some(input);
        self
    }
    /// <p>The client application type in the CreateConnection request. For example, <code>AWS_MANAGED</code> or <code>USER_MANAGED</code>.</p>
    pub fn set_o_auth2_client_application(mut self, input: ::std::option::Option<crate::types::OAuth2ClientApplication>) -> Self {
        self.o_auth2_client_application = input;
        self
    }
    /// <p>The client application type in the CreateConnection request. For example, <code>AWS_MANAGED</code> or <code>USER_MANAGED</code>.</p>
    pub fn get_o_auth2_client_application(&self) -> &::std::option::Option<crate::types::OAuth2ClientApplication> {
        &self.o_auth2_client_application
    }
    /// <p>The URL of the provider's authentication server, to exchange an authorization code for an access token.</p>
    pub fn token_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the provider's authentication server, to exchange an authorization code for an access token.</p>
    pub fn set_token_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_url = input;
        self
    }
    /// <p>The URL of the provider's authentication server, to exchange an authorization code for an access token.</p>
    pub fn get_token_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_url
    }
    /// Adds a key-value pair to `token_url_parameters_map`.
    ///
    /// To override the contents of this collection use [`set_token_url_parameters_map`](Self::set_token_url_parameters_map).
    ///
    /// <p>A map of parameters that are added to the token <code>GET</code> request.</p>
    pub fn token_url_parameters_map(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.token_url_parameters_map.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.token_url_parameters_map = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of parameters that are added to the token <code>GET</code> request.</p>
    pub fn set_token_url_parameters_map(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.token_url_parameters_map = input;
        self
    }
    /// <p>A map of parameters that are added to the token <code>GET</code> request.</p>
    pub fn get_token_url_parameters_map(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.token_url_parameters_map
    }
    /// <p>The set of properties required for the the OAuth2 <code>AUTHORIZATION_CODE</code> grant type.</p>
    pub fn authorization_code_properties(mut self, input: crate::types::AuthorizationCodeProperties) -> Self {
        self.authorization_code_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The set of properties required for the the OAuth2 <code>AUTHORIZATION_CODE</code> grant type.</p>
    pub fn set_authorization_code_properties(mut self, input: ::std::option::Option<crate::types::AuthorizationCodeProperties>) -> Self {
        self.authorization_code_properties = input;
        self
    }
    /// <p>The set of properties required for the the OAuth2 <code>AUTHORIZATION_CODE</code> grant type.</p>
    pub fn get_authorization_code_properties(&self) -> &::std::option::Option<crate::types::AuthorizationCodeProperties> {
        &self.authorization_code_properties
    }
    /// <p>The credentials used when the authentication type is OAuth2 authentication.</p>
    pub fn o_auth2_credentials(mut self, input: crate::types::OAuth2Credentials) -> Self {
        self.o_auth2_credentials = ::std::option::Option::Some(input);
        self
    }
    /// <p>The credentials used when the authentication type is OAuth2 authentication.</p>
    pub fn set_o_auth2_credentials(mut self, input: ::std::option::Option<crate::types::OAuth2Credentials>) -> Self {
        self.o_auth2_credentials = input;
        self
    }
    /// <p>The credentials used when the authentication type is OAuth2 authentication.</p>
    pub fn get_o_auth2_credentials(&self) -> &::std::option::Option<crate::types::OAuth2Credentials> {
        &self.o_auth2_credentials
    }
    /// Consumes the builder and constructs a [`OAuth2PropertiesInput`](crate::types::OAuth2PropertiesInput).
    pub fn build(self) -> crate::types::OAuth2PropertiesInput {
        crate::types::OAuth2PropertiesInput {
            o_auth2_grant_type: self.o_auth2_grant_type,
            o_auth2_client_application: self.o_auth2_client_application,
            token_url: self.token_url,
            token_url_parameters_map: self.token_url_parameters_map,
            authorization_code_properties: self.authorization_code_properties,
            o_auth2_credentials: self.o_auth2_credentials,
        }
    }
}
