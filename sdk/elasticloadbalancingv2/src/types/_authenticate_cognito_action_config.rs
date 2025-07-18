// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request parameters to use when integrating with Amazon Cognito to authenticate users.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuthenticateCognitoActionConfig {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Cognito user pool.</p>
    pub user_pool_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Cognito user pool client.</p>
    pub user_pool_client_id: ::std::option::Option<::std::string::String>,
    /// <p>The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.</p>
    pub user_pool_domain: ::std::option::Option<::std::string::String>,
    /// <p>The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.</p>
    pub session_cookie_name: ::std::option::Option<::std::string::String>,
    /// <p>The set of user claims to be requested from the IdP. The default is <code>openid</code>.</p>
    /// <p>To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.</p>
    pub scope: ::std::option::Option<::std::string::String>,
    /// <p>The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).</p>
    pub session_timeout: ::std::option::Option<i64>,
    /// <p>The query parameters (up to 10) to include in the redirect request to the authorization endpoint.</p>
    pub authentication_request_extra_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The behavior if the user is not authenticated. The following are possible values:</p>
    /// <ul>
    /// <li>
    /// <p>deny<code></code> - Return an HTTP 401 Unauthorized error.</p></li>
    /// <li>
    /// <p>allow<code></code> - Allow the request to be forwarded to the target.</p></li>
    /// <li>
    /// <p>authenticate<code></code> - Redirect the request to the IdP authorization endpoint. This is the default value.</p></li>
    /// </ul>
    pub on_unauthenticated_request: ::std::option::Option<crate::types::AuthenticateCognitoActionConditionalBehaviorEnum>,
}
impl AuthenticateCognitoActionConfig {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Cognito user pool.</p>
    pub fn user_pool_arn(&self) -> ::std::option::Option<&str> {
        self.user_pool_arn.as_deref()
    }
    /// <p>The ID of the Amazon Cognito user pool client.</p>
    pub fn user_pool_client_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_client_id.as_deref()
    }
    /// <p>The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.</p>
    pub fn user_pool_domain(&self) -> ::std::option::Option<&str> {
        self.user_pool_domain.as_deref()
    }
    /// <p>The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.</p>
    pub fn session_cookie_name(&self) -> ::std::option::Option<&str> {
        self.session_cookie_name.as_deref()
    }
    /// <p>The set of user claims to be requested from the IdP. The default is <code>openid</code>.</p>
    /// <p>To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.</p>
    pub fn scope(&self) -> ::std::option::Option<&str> {
        self.scope.as_deref()
    }
    /// <p>The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).</p>
    pub fn session_timeout(&self) -> ::std::option::Option<i64> {
        self.session_timeout
    }
    /// <p>The query parameters (up to 10) to include in the redirect request to the authorization endpoint.</p>
    pub fn authentication_request_extra_params(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.authentication_request_extra_params.as_ref()
    }
    /// <p>The behavior if the user is not authenticated. The following are possible values:</p>
    /// <ul>
    /// <li>
    /// <p>deny<code></code> - Return an HTTP 401 Unauthorized error.</p></li>
    /// <li>
    /// <p>allow<code></code> - Allow the request to be forwarded to the target.</p></li>
    /// <li>
    /// <p>authenticate<code></code> - Redirect the request to the IdP authorization endpoint. This is the default value.</p></li>
    /// </ul>
    pub fn on_unauthenticated_request(&self) -> ::std::option::Option<&crate::types::AuthenticateCognitoActionConditionalBehaviorEnum> {
        self.on_unauthenticated_request.as_ref()
    }
}
impl AuthenticateCognitoActionConfig {
    /// Creates a new builder-style object to manufacture [`AuthenticateCognitoActionConfig`](crate::types::AuthenticateCognitoActionConfig).
    pub fn builder() -> crate::types::builders::AuthenticateCognitoActionConfigBuilder {
        crate::types::builders::AuthenticateCognitoActionConfigBuilder::default()
    }
}

/// A builder for [`AuthenticateCognitoActionConfig`](crate::types::AuthenticateCognitoActionConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuthenticateCognitoActionConfigBuilder {
    pub(crate) user_pool_arn: ::std::option::Option<::std::string::String>,
    pub(crate) user_pool_client_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_pool_domain: ::std::option::Option<::std::string::String>,
    pub(crate) session_cookie_name: ::std::option::Option<::std::string::String>,
    pub(crate) scope: ::std::option::Option<::std::string::String>,
    pub(crate) session_timeout: ::std::option::Option<i64>,
    pub(crate) authentication_request_extra_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) on_unauthenticated_request: ::std::option::Option<crate::types::AuthenticateCognitoActionConditionalBehaviorEnum>,
}
impl AuthenticateCognitoActionConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Cognito user pool.</p>
    /// This field is required.
    pub fn user_pool_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Cognito user pool.</p>
    pub fn set_user_pool_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Cognito user pool.</p>
    pub fn get_user_pool_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_arn
    }
    /// <p>The ID of the Amazon Cognito user pool client.</p>
    /// This field is required.
    pub fn user_pool_client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Cognito user pool client.</p>
    pub fn set_user_pool_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_client_id = input;
        self
    }
    /// <p>The ID of the Amazon Cognito user pool client.</p>
    pub fn get_user_pool_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_client_id
    }
    /// <p>The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.</p>
    /// This field is required.
    pub fn user_pool_domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.</p>
    pub fn set_user_pool_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_domain = input;
        self
    }
    /// <p>The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.</p>
    pub fn get_user_pool_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_domain
    }
    /// <p>The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.</p>
    pub fn session_cookie_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_cookie_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.</p>
    pub fn set_session_cookie_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_cookie_name = input;
        self
    }
    /// <p>The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.</p>
    pub fn get_session_cookie_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_cookie_name
    }
    /// <p>The set of user claims to be requested from the IdP. The default is <code>openid</code>.</p>
    /// <p>To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.</p>
    pub fn scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The set of user claims to be requested from the IdP. The default is <code>openid</code>.</p>
    /// <p>To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope = input;
        self
    }
    /// <p>The set of user claims to be requested from the IdP. The default is <code>openid</code>.</p>
    /// <p>To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.</p>
    pub fn get_scope(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope
    }
    /// <p>The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).</p>
    pub fn session_timeout(mut self, input: i64) -> Self {
        self.session_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).</p>
    pub fn set_session_timeout(mut self, input: ::std::option::Option<i64>) -> Self {
        self.session_timeout = input;
        self
    }
    /// <p>The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).</p>
    pub fn get_session_timeout(&self) -> &::std::option::Option<i64> {
        &self.session_timeout
    }
    /// Adds a key-value pair to `authentication_request_extra_params`.
    ///
    /// To override the contents of this collection use [`set_authentication_request_extra_params`](Self::set_authentication_request_extra_params).
    ///
    /// <p>The query parameters (up to 10) to include in the redirect request to the authorization endpoint.</p>
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
    /// <p>The query parameters (up to 10) to include in the redirect request to the authorization endpoint.</p>
    pub fn set_authentication_request_extra_params(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.authentication_request_extra_params = input;
        self
    }
    /// <p>The query parameters (up to 10) to include in the redirect request to the authorization endpoint.</p>
    pub fn get_authentication_request_extra_params(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.authentication_request_extra_params
    }
    /// <p>The behavior if the user is not authenticated. The following are possible values:</p>
    /// <ul>
    /// <li>
    /// <p>deny<code></code> - Return an HTTP 401 Unauthorized error.</p></li>
    /// <li>
    /// <p>allow<code></code> - Allow the request to be forwarded to the target.</p></li>
    /// <li>
    /// <p>authenticate<code></code> - Redirect the request to the IdP authorization endpoint. This is the default value.</p></li>
    /// </ul>
    pub fn on_unauthenticated_request(mut self, input: crate::types::AuthenticateCognitoActionConditionalBehaviorEnum) -> Self {
        self.on_unauthenticated_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>The behavior if the user is not authenticated. The following are possible values:</p>
    /// <ul>
    /// <li>
    /// <p>deny<code></code> - Return an HTTP 401 Unauthorized error.</p></li>
    /// <li>
    /// <p>allow<code></code> - Allow the request to be forwarded to the target.</p></li>
    /// <li>
    /// <p>authenticate<code></code> - Redirect the request to the IdP authorization endpoint. This is the default value.</p></li>
    /// </ul>
    pub fn set_on_unauthenticated_request(
        mut self,
        input: ::std::option::Option<crate::types::AuthenticateCognitoActionConditionalBehaviorEnum>,
    ) -> Self {
        self.on_unauthenticated_request = input;
        self
    }
    /// <p>The behavior if the user is not authenticated. The following are possible values:</p>
    /// <ul>
    /// <li>
    /// <p>deny<code></code> - Return an HTTP 401 Unauthorized error.</p></li>
    /// <li>
    /// <p>allow<code></code> - Allow the request to be forwarded to the target.</p></li>
    /// <li>
    /// <p>authenticate<code></code> - Redirect the request to the IdP authorization endpoint. This is the default value.</p></li>
    /// </ul>
    pub fn get_on_unauthenticated_request(&self) -> &::std::option::Option<crate::types::AuthenticateCognitoActionConditionalBehaviorEnum> {
        &self.on_unauthenticated_request
    }
    /// Consumes the builder and constructs a [`AuthenticateCognitoActionConfig`](crate::types::AuthenticateCognitoActionConfig).
    pub fn build(self) -> crate::types::AuthenticateCognitoActionConfig {
        crate::types::AuthenticateCognitoActionConfig {
            user_pool_arn: self.user_pool_arn,
            user_pool_client_id: self.user_pool_client_id,
            user_pool_domain: self.user_pool_domain,
            session_cookie_name: self.session_cookie_name,
            scope: self.scope,
            session_timeout: self.session_timeout,
            authentication_request_extra_params: self.authentication_request_extra_params,
            on_unauthenticated_request: self.on_unauthenticated_request,
        }
    }
}
