// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateTokenWithIamInput {
    /// <p>The unique identifier string for the client or application. This value is an application ARN that has OAuth grants configured.</p>
    pub client_id: ::std::option::Option<::std::string::String>,
    /// <p>Supports the following OAuth grant types: Authorization Code, Refresh Token, JWT Bearer, and Token Exchange. Specify one of the following values, depending on the grant type that you want:</p>
    /// <p>* Authorization Code - <code>authorization_code</code></p>
    /// <p>* Refresh Token - <code>refresh_token</code></p>
    /// <p>* JWT Bearer - <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code></p>
    /// <p>* Token Exchange - <code>urn:ietf:params:oauth:grant-type:token-exchange</code></p>
    pub grant_type: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Authorization Code grant type. This short-lived code is used to identify this authorization request. The code is obtained through a redirect from IAM Identity Center to a redirect URI persisted in the Authorization Code GrantOptions for the application.</p>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Refresh Token grant type. This token is used to refresh short-lived tokens, such as the access token, that might expire.</p>
    /// <p>For more information about the features and limitations of the current IAM Identity Center OIDC implementation, see <i>Considerations for Using this Guide</i> in the <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html">IAM Identity Center OIDC API Reference</a>.</p>
    pub refresh_token: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the JWT Bearer grant type. This value specifies the JSON Web Token (JWT) issued by a trusted token issuer. To authorize a trusted token issuer, configure the JWT Bearer GrantOptions for the application.</p>
    pub assertion: ::std::option::Option<::std::string::String>,
    /// <p>The list of scopes for which authorization is requested. The access token that is issued is limited to the scopes that are granted. If the value is not specified, IAM Identity Center authorizes all scopes configured for the application, including the following default scopes: <code>openid</code>, <code>aws</code>, <code>sts:identity_context</code>.</p>
    pub scope: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Used only when calling this API for the Authorization Code grant type. This value specifies the location of the client or application that has registered to receive the authorization code.</p>
    pub redirect_uri: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the subject of the exchange. The value of the subject token must be an access token issued by IAM Identity Center to a different client or application. The access token must have authorized scopes that indicate the requested application as a target audience.</p>
    pub subject_token: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that is passed as the subject of the exchange. The following value is supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    pub subject_token_type: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that the requester can receive. The following values are supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    /// <p>* Refresh Token - <code>urn:ietf:params:oauth:token-type:refresh_token</code></p>
    pub requested_token_type: ::std::option::Option<::std::string::String>,
    /// <p>Used only when calling this API for the Authorization Code grant type. This value is generated by the client and presented to validate the original code challenge value the client passed at authorization time.</p>
    pub code_verifier: ::std::option::Option<::std::string::String>,
}
impl CreateTokenWithIamInput {
    /// <p>The unique identifier string for the client or application. This value is an application ARN that has OAuth grants configured.</p>
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }
    /// <p>Supports the following OAuth grant types: Authorization Code, Refresh Token, JWT Bearer, and Token Exchange. Specify one of the following values, depending on the grant type that you want:</p>
    /// <p>* Authorization Code - <code>authorization_code</code></p>
    /// <p>* Refresh Token - <code>refresh_token</code></p>
    /// <p>* JWT Bearer - <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code></p>
    /// <p>* Token Exchange - <code>urn:ietf:params:oauth:grant-type:token-exchange</code></p>
    pub fn grant_type(&self) -> ::std::option::Option<&str> {
        self.grant_type.as_deref()
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This short-lived code is used to identify this authorization request. The code is obtained through a redirect from IAM Identity Center to a redirect URI persisted in the Authorization Code GrantOptions for the application.</p>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>Used only when calling this API for the Refresh Token grant type. This token is used to refresh short-lived tokens, such as the access token, that might expire.</p>
    /// <p>For more information about the features and limitations of the current IAM Identity Center OIDC implementation, see <i>Considerations for Using this Guide</i> in the <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html">IAM Identity Center OIDC API Reference</a>.</p>
    pub fn refresh_token(&self) -> ::std::option::Option<&str> {
        self.refresh_token.as_deref()
    }
    /// <p>Used only when calling this API for the JWT Bearer grant type. This value specifies the JSON Web Token (JWT) issued by a trusted token issuer. To authorize a trusted token issuer, configure the JWT Bearer GrantOptions for the application.</p>
    pub fn assertion(&self) -> ::std::option::Option<&str> {
        self.assertion.as_deref()
    }
    /// <p>The list of scopes for which authorization is requested. The access token that is issued is limited to the scopes that are granted. If the value is not specified, IAM Identity Center authorizes all scopes configured for the application, including the following default scopes: <code>openid</code>, <code>aws</code>, <code>sts:identity_context</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.scope.is_none()`.
    pub fn scope(&self) -> &[::std::string::String] {
        self.scope.as_deref().unwrap_or_default()
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value specifies the location of the client or application that has registered to receive the authorization code.</p>
    pub fn redirect_uri(&self) -> ::std::option::Option<&str> {
        self.redirect_uri.as_deref()
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the subject of the exchange. The value of the subject token must be an access token issued by IAM Identity Center to a different client or application. The access token must have authorized scopes that indicate the requested application as a target audience.</p>
    pub fn subject_token(&self) -> ::std::option::Option<&str> {
        self.subject_token.as_deref()
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that is passed as the subject of the exchange. The following value is supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    pub fn subject_token_type(&self) -> ::std::option::Option<&str> {
        self.subject_token_type.as_deref()
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that the requester can receive. The following values are supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    /// <p>* Refresh Token - <code>urn:ietf:params:oauth:token-type:refresh_token</code></p>
    pub fn requested_token_type(&self) -> ::std::option::Option<&str> {
        self.requested_token_type.as_deref()
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value is generated by the client and presented to validate the original code challenge value the client passed at authorization time.</p>
    pub fn code_verifier(&self) -> ::std::option::Option<&str> {
        self.code_verifier.as_deref()
    }
}
impl ::std::fmt::Debug for CreateTokenWithIamInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateTokenWithIamInput");
        formatter.field("client_id", &self.client_id);
        formatter.field("grant_type", &self.grant_type);
        formatter.field("code", &self.code);
        formatter.field("refresh_token", &"*** Sensitive Data Redacted ***");
        formatter.field("assertion", &"*** Sensitive Data Redacted ***");
        formatter.field("scope", &self.scope);
        formatter.field("redirect_uri", &self.redirect_uri);
        formatter.field("subject_token", &"*** Sensitive Data Redacted ***");
        formatter.field("subject_token_type", &self.subject_token_type);
        formatter.field("requested_token_type", &self.requested_token_type);
        formatter.field("code_verifier", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateTokenWithIamInput {
    /// Creates a new builder-style object to manufacture [`CreateTokenWithIamInput`](crate::operation::create_token_with_iam::CreateTokenWithIamInput).
    pub fn builder() -> crate::operation::create_token_with_iam::builders::CreateTokenWithIamInputBuilder {
        crate::operation::create_token_with_iam::builders::CreateTokenWithIamInputBuilder::default()
    }
}

/// A builder for [`CreateTokenWithIamInput`](crate::operation::create_token_with_iam::CreateTokenWithIamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateTokenWithIamInputBuilder {
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
    pub(crate) grant_type: ::std::option::Option<::std::string::String>,
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) refresh_token: ::std::option::Option<::std::string::String>,
    pub(crate) assertion: ::std::option::Option<::std::string::String>,
    pub(crate) scope: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) redirect_uri: ::std::option::Option<::std::string::String>,
    pub(crate) subject_token: ::std::option::Option<::std::string::String>,
    pub(crate) subject_token_type: ::std::option::Option<::std::string::String>,
    pub(crate) requested_token_type: ::std::option::Option<::std::string::String>,
    pub(crate) code_verifier: ::std::option::Option<::std::string::String>,
}
impl CreateTokenWithIamInputBuilder {
    /// <p>The unique identifier string for the client or application. This value is an application ARN that has OAuth grants configured.</p>
    /// This field is required.
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier string for the client or application. This value is an application ARN that has OAuth grants configured.</p>
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }
    /// <p>The unique identifier string for the client or application. This value is an application ARN that has OAuth grants configured.</p>
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }
    /// <p>Supports the following OAuth grant types: Authorization Code, Refresh Token, JWT Bearer, and Token Exchange. Specify one of the following values, depending on the grant type that you want:</p>
    /// <p>* Authorization Code - <code>authorization_code</code></p>
    /// <p>* Refresh Token - <code>refresh_token</code></p>
    /// <p>* JWT Bearer - <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code></p>
    /// <p>* Token Exchange - <code>urn:ietf:params:oauth:grant-type:token-exchange</code></p>
    /// This field is required.
    pub fn grant_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grant_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Supports the following OAuth grant types: Authorization Code, Refresh Token, JWT Bearer, and Token Exchange. Specify one of the following values, depending on the grant type that you want:</p>
    /// <p>* Authorization Code - <code>authorization_code</code></p>
    /// <p>* Refresh Token - <code>refresh_token</code></p>
    /// <p>* JWT Bearer - <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code></p>
    /// <p>* Token Exchange - <code>urn:ietf:params:oauth:grant-type:token-exchange</code></p>
    pub fn set_grant_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grant_type = input;
        self
    }
    /// <p>Supports the following OAuth grant types: Authorization Code, Refresh Token, JWT Bearer, and Token Exchange. Specify one of the following values, depending on the grant type that you want:</p>
    /// <p>* Authorization Code - <code>authorization_code</code></p>
    /// <p>* Refresh Token - <code>refresh_token</code></p>
    /// <p>* JWT Bearer - <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code></p>
    /// <p>* Token Exchange - <code>urn:ietf:params:oauth:grant-type:token-exchange</code></p>
    pub fn get_grant_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.grant_type
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This short-lived code is used to identify this authorization request. The code is obtained through a redirect from IAM Identity Center to a redirect URI persisted in the Authorization Code GrantOptions for the application.</p>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This short-lived code is used to identify this authorization request. The code is obtained through a redirect from IAM Identity Center to a redirect URI persisted in the Authorization Code GrantOptions for the application.</p>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This short-lived code is used to identify this authorization request. The code is obtained through a redirect from IAM Identity Center to a redirect URI persisted in the Authorization Code GrantOptions for the application.</p>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>Used only when calling this API for the Refresh Token grant type. This token is used to refresh short-lived tokens, such as the access token, that might expire.</p>
    /// <p>For more information about the features and limitations of the current IAM Identity Center OIDC implementation, see <i>Considerations for Using this Guide</i> in the <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html">IAM Identity Center OIDC API Reference</a>.</p>
    pub fn refresh_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.refresh_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Refresh Token grant type. This token is used to refresh short-lived tokens, such as the access token, that might expire.</p>
    /// <p>For more information about the features and limitations of the current IAM Identity Center OIDC implementation, see <i>Considerations for Using this Guide</i> in the <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html">IAM Identity Center OIDC API Reference</a>.</p>
    pub fn set_refresh_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.refresh_token = input;
        self
    }
    /// <p>Used only when calling this API for the Refresh Token grant type. This token is used to refresh short-lived tokens, such as the access token, that might expire.</p>
    /// <p>For more information about the features and limitations of the current IAM Identity Center OIDC implementation, see <i>Considerations for Using this Guide</i> in the <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html">IAM Identity Center OIDC API Reference</a>.</p>
    pub fn get_refresh_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.refresh_token
    }
    /// <p>Used only when calling this API for the JWT Bearer grant type. This value specifies the JSON Web Token (JWT) issued by a trusted token issuer. To authorize a trusted token issuer, configure the JWT Bearer GrantOptions for the application.</p>
    pub fn assertion(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assertion = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the JWT Bearer grant type. This value specifies the JSON Web Token (JWT) issued by a trusted token issuer. To authorize a trusted token issuer, configure the JWT Bearer GrantOptions for the application.</p>
    pub fn set_assertion(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assertion = input;
        self
    }
    /// <p>Used only when calling this API for the JWT Bearer grant type. This value specifies the JSON Web Token (JWT) issued by a trusted token issuer. To authorize a trusted token issuer, configure the JWT Bearer GrantOptions for the application.</p>
    pub fn get_assertion(&self) -> &::std::option::Option<::std::string::String> {
        &self.assertion
    }
    /// Appends an item to `scope`.
    ///
    /// To override the contents of this collection use [`set_scope`](Self::set_scope).
    ///
    /// <p>The list of scopes for which authorization is requested. The access token that is issued is limited to the scopes that are granted. If the value is not specified, IAM Identity Center authorizes all scopes configured for the application, including the following default scopes: <code>openid</code>, <code>aws</code>, <code>sts:identity_context</code>.</p>
    pub fn scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.scope.unwrap_or_default();
        v.push(input.into());
        self.scope = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of scopes for which authorization is requested. The access token that is issued is limited to the scopes that are granted. If the value is not specified, IAM Identity Center authorizes all scopes configured for the application, including the following default scopes: <code>openid</code>, <code>aws</code>, <code>sts:identity_context</code>.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.scope = input;
        self
    }
    /// <p>The list of scopes for which authorization is requested. The access token that is issued is limited to the scopes that are granted. If the value is not specified, IAM Identity Center authorizes all scopes configured for the application, including the following default scopes: <code>openid</code>, <code>aws</code>, <code>sts:identity_context</code>.</p>
    pub fn get_scope(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.scope
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value specifies the location of the client or application that has registered to receive the authorization code.</p>
    pub fn redirect_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.redirect_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value specifies the location of the client or application that has registered to receive the authorization code.</p>
    pub fn set_redirect_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.redirect_uri = input;
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value specifies the location of the client or application that has registered to receive the authorization code.</p>
    pub fn get_redirect_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.redirect_uri
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the subject of the exchange. The value of the subject token must be an access token issued by IAM Identity Center to a different client or application. The access token must have authorized scopes that indicate the requested application as a target audience.</p>
    pub fn subject_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the subject of the exchange. The value of the subject token must be an access token issued by IAM Identity Center to a different client or application. The access token must have authorized scopes that indicate the requested application as a target audience.</p>
    pub fn set_subject_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_token = input;
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the subject of the exchange. The value of the subject token must be an access token issued by IAM Identity Center to a different client or application. The access token must have authorized scopes that indicate the requested application as a target audience.</p>
    pub fn get_subject_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_token
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that is passed as the subject of the exchange. The following value is supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    pub fn subject_token_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_token_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that is passed as the subject of the exchange. The following value is supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    pub fn set_subject_token_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_token_type = input;
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that is passed as the subject of the exchange. The following value is supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    pub fn get_subject_token_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_token_type
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that the requester can receive. The following values are supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    /// <p>* Refresh Token - <code>urn:ietf:params:oauth:token-type:refresh_token</code></p>
    pub fn requested_token_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.requested_token_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that the requester can receive. The following values are supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    /// <p>* Refresh Token - <code>urn:ietf:params:oauth:token-type:refresh_token</code></p>
    pub fn set_requested_token_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.requested_token_type = input;
        self
    }
    /// <p>Used only when calling this API for the Token Exchange grant type. This value specifies the type of token that the requester can receive. The following values are supported:</p>
    /// <p>* Access Token - <code>urn:ietf:params:oauth:token-type:access_token</code></p>
    /// <p>* Refresh Token - <code>urn:ietf:params:oauth:token-type:refresh_token</code></p>
    pub fn get_requested_token_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.requested_token_type
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value is generated by the client and presented to validate the original code challenge value the client passed at authorization time.</p>
    pub fn code_verifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_verifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value is generated by the client and presented to validate the original code challenge value the client passed at authorization time.</p>
    pub fn set_code_verifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_verifier = input;
        self
    }
    /// <p>Used only when calling this API for the Authorization Code grant type. This value is generated by the client and presented to validate the original code challenge value the client passed at authorization time.</p>
    pub fn get_code_verifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_verifier
    }
    /// Consumes the builder and constructs a [`CreateTokenWithIamInput`](crate::operation::create_token_with_iam::CreateTokenWithIamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_token_with_iam::CreateTokenWithIamInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_token_with_iam::CreateTokenWithIamInput {
            client_id: self.client_id,
            grant_type: self.grant_type,
            code: self.code,
            refresh_token: self.refresh_token,
            assertion: self.assertion,
            scope: self.scope,
            redirect_uri: self.redirect_uri,
            subject_token: self.subject_token,
            subject_token_type: self.subject_token_type,
            requested_token_type: self.requested_token_type,
            code_verifier: self.code_verifier,
        })
    }
}
impl ::std::fmt::Debug for CreateTokenWithIamInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateTokenWithIamInputBuilder");
        formatter.field("client_id", &self.client_id);
        formatter.field("grant_type", &self.grant_type);
        formatter.field("code", &self.code);
        formatter.field("refresh_token", &"*** Sensitive Data Redacted ***");
        formatter.field("assertion", &"*** Sensitive Data Redacted ***");
        formatter.field("scope", &self.scope);
        formatter.field("redirect_uri", &self.redirect_uri);
        formatter.field("subject_token", &"*** Sensitive Data Redacted ***");
        formatter.field("subject_token_type", &self.subject_token_type);
        formatter.field("requested_token_type", &self.requested_token_type);
        formatter.field("code_verifier", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
