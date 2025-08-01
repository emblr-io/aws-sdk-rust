// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The connector-specific profile credentials required when using Amazon Redshift.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RedshiftConnectorProfileCredentials {
    /// <p>The name of the user.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>The password that corresponds to the user name.</p>
    pub password: ::std::option::Option<::std::string::String>,
}
impl RedshiftConnectorProfileCredentials {
    /// <p>The name of the user.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>The password that corresponds to the user name.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
}
impl ::std::fmt::Debug for RedshiftConnectorProfileCredentials {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RedshiftConnectorProfileCredentials");
        formatter.field("username", &self.username);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl RedshiftConnectorProfileCredentials {
    /// Creates a new builder-style object to manufacture [`RedshiftConnectorProfileCredentials`](crate::types::RedshiftConnectorProfileCredentials).
    pub fn builder() -> crate::types::builders::RedshiftConnectorProfileCredentialsBuilder {
        crate::types::builders::RedshiftConnectorProfileCredentialsBuilder::default()
    }
}

/// A builder for [`RedshiftConnectorProfileCredentials`](crate::types::RedshiftConnectorProfileCredentials).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RedshiftConnectorProfileCredentialsBuilder {
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
}
impl RedshiftConnectorProfileCredentialsBuilder {
    /// <p>The name of the user.</p>
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The name of the user.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>The password that corresponds to the user name.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password that corresponds to the user name.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The password that corresponds to the user name.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// Consumes the builder and constructs a [`RedshiftConnectorProfileCredentials`](crate::types::RedshiftConnectorProfileCredentials).
    pub fn build(self) -> crate::types::RedshiftConnectorProfileCredentials {
        crate::types::RedshiftConnectorProfileCredentials {
            username: self.username,
            password: self.password,
        }
    }
}
impl ::std::fmt::Debug for RedshiftConnectorProfileCredentialsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RedshiftConnectorProfileCredentialsBuilder");
        formatter.field("username", &self.username);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
