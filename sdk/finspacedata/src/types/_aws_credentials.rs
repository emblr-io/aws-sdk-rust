// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The credentials required to access the external Dataview from the S3 location.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AwsCredentials {
    /// <p>The unique identifier for the security credentials.</p>
    pub access_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The secret access key that can be used to sign requests.</p>
    pub secret_access_key: ::std::option::Option<::std::string::String>,
    /// <p>The token that users must pass to use the credentials.</p>
    pub session_token: ::std::option::Option<::std::string::String>,
    /// <p>The Epoch time when the current credentials expire.</p>
    pub expiration: i64,
}
impl AwsCredentials {
    /// <p>The unique identifier for the security credentials.</p>
    pub fn access_key_id(&self) -> ::std::option::Option<&str> {
        self.access_key_id.as_deref()
    }
    /// <p>The secret access key that can be used to sign requests.</p>
    pub fn secret_access_key(&self) -> ::std::option::Option<&str> {
        self.secret_access_key.as_deref()
    }
    /// <p>The token that users must pass to use the credentials.</p>
    pub fn session_token(&self) -> ::std::option::Option<&str> {
        self.session_token.as_deref()
    }
    /// <p>The Epoch time when the current credentials expire.</p>
    pub fn expiration(&self) -> i64 {
        self.expiration
    }
}
impl ::std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AwsCredentials");
        formatter.field("access_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("secret_access_key", &"*** Sensitive Data Redacted ***");
        formatter.field("session_token", &"*** Sensitive Data Redacted ***");
        formatter.field("expiration", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl AwsCredentials {
    /// Creates a new builder-style object to manufacture [`AwsCredentials`](crate::types::AwsCredentials).
    pub fn builder() -> crate::types::builders::AwsCredentialsBuilder {
        crate::types::builders::AwsCredentialsBuilder::default()
    }
}

/// A builder for [`AwsCredentials`](crate::types::AwsCredentials).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AwsCredentialsBuilder {
    pub(crate) access_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) secret_access_key: ::std::option::Option<::std::string::String>,
    pub(crate) session_token: ::std::option::Option<::std::string::String>,
    pub(crate) expiration: ::std::option::Option<i64>,
}
impl AwsCredentialsBuilder {
    /// <p>The unique identifier for the security credentials.</p>
    pub fn access_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the security credentials.</p>
    pub fn set_access_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_key_id = input;
        self
    }
    /// <p>The unique identifier for the security credentials.</p>
    pub fn get_access_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_key_id
    }
    /// <p>The secret access key that can be used to sign requests.</p>
    pub fn secret_access_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_access_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The secret access key that can be used to sign requests.</p>
    pub fn set_secret_access_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_access_key = input;
        self
    }
    /// <p>The secret access key that can be used to sign requests.</p>
    pub fn get_secret_access_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_access_key
    }
    /// <p>The token that users must pass to use the credentials.</p>
    pub fn session_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that users must pass to use the credentials.</p>
    pub fn set_session_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_token = input;
        self
    }
    /// <p>The token that users must pass to use the credentials.</p>
    pub fn get_session_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_token
    }
    /// <p>The Epoch time when the current credentials expire.</p>
    pub fn expiration(mut self, input: i64) -> Self {
        self.expiration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Epoch time when the current credentials expire.</p>
    pub fn set_expiration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.expiration = input;
        self
    }
    /// <p>The Epoch time when the current credentials expire.</p>
    pub fn get_expiration(&self) -> &::std::option::Option<i64> {
        &self.expiration
    }
    /// Consumes the builder and constructs a [`AwsCredentials`](crate::types::AwsCredentials).
    pub fn build(self) -> crate::types::AwsCredentials {
        crate::types::AwsCredentials {
            access_key_id: self.access_key_id,
            secret_access_key: self.secret_access_key,
            session_token: self.session_token,
            expiration: self.expiration.unwrap_or_default(),
        }
    }
}
impl ::std::fmt::Debug for AwsCredentialsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AwsCredentialsBuilder");
        formatter.field("access_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("secret_access_key", &"*** Sensitive Data Redacted ***");
        formatter.field("session_token", &"*** Sensitive Data Redacted ***");
        formatter.field("expiration", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
