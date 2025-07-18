// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies configuration information for a customer-managed Secrets Manager secret where a storage location authentication token or secret key is stored in plain text. This configuration includes the secret ARN, and the ARN for an IAM role that provides access to the secret.</p><note>
/// <p>You can use either <code>CmkSecretConfig</code> or <code>CustomSecretConfig</code> to provide credentials for a <code>CreateLocation</code> request. Do not provide both parameters for the same request.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomSecretConfig {
    /// <p>Specifies the ARN for an Secrets Manager secret.</p>
    pub secret_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ARN for the Identity and Access Management role that DataSync uses to access the secret specified for <code>SecretArn</code>.</p>
    pub secret_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl CustomSecretConfig {
    /// <p>Specifies the ARN for an Secrets Manager secret.</p>
    pub fn secret_arn(&self) -> ::std::option::Option<&str> {
        self.secret_arn.as_deref()
    }
    /// <p>Specifies the ARN for the Identity and Access Management role that DataSync uses to access the secret specified for <code>SecretArn</code>.</p>
    pub fn secret_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.secret_access_role_arn.as_deref()
    }
}
impl CustomSecretConfig {
    /// Creates a new builder-style object to manufacture [`CustomSecretConfig`](crate::types::CustomSecretConfig).
    pub fn builder() -> crate::types::builders::CustomSecretConfigBuilder {
        crate::types::builders::CustomSecretConfigBuilder::default()
    }
}

/// A builder for [`CustomSecretConfig`](crate::types::CustomSecretConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomSecretConfigBuilder {
    pub(crate) secret_arn: ::std::option::Option<::std::string::String>,
    pub(crate) secret_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl CustomSecretConfigBuilder {
    /// <p>Specifies the ARN for an Secrets Manager secret.</p>
    pub fn secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN for an Secrets Manager secret.</p>
    pub fn set_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_arn = input;
        self
    }
    /// <p>Specifies the ARN for an Secrets Manager secret.</p>
    pub fn get_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_arn
    }
    /// <p>Specifies the ARN for the Identity and Access Management role that DataSync uses to access the secret specified for <code>SecretArn</code>.</p>
    pub fn secret_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN for the Identity and Access Management role that DataSync uses to access the secret specified for <code>SecretArn</code>.</p>
    pub fn set_secret_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_access_role_arn = input;
        self
    }
    /// <p>Specifies the ARN for the Identity and Access Management role that DataSync uses to access the secret specified for <code>SecretArn</code>.</p>
    pub fn get_secret_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_access_role_arn
    }
    /// Consumes the builder and constructs a [`CustomSecretConfig`](crate::types::CustomSecretConfig).
    pub fn build(self) -> crate::types::CustomSecretConfig {
        crate::types::CustomSecretConfig {
            secret_arn: self.secret_arn,
            secret_access_role_arn: self.secret_access_role_arn,
        }
    }
}
