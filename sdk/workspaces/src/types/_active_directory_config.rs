// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the Active Directory config.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActiveDirectoryConfig {
    /// <p>The name of the domain.</p>
    pub domain_name: ::std::string::String,
    /// <p>Indicates the secret ARN on the service account.</p>
    pub service_account_secret_arn: ::std::string::String,
}
impl ActiveDirectoryConfig {
    /// <p>The name of the domain.</p>
    pub fn domain_name(&self) -> &str {
        use std::ops::Deref;
        self.domain_name.deref()
    }
    /// <p>Indicates the secret ARN on the service account.</p>
    pub fn service_account_secret_arn(&self) -> &str {
        use std::ops::Deref;
        self.service_account_secret_arn.deref()
    }
}
impl ActiveDirectoryConfig {
    /// Creates a new builder-style object to manufacture [`ActiveDirectoryConfig`](crate::types::ActiveDirectoryConfig).
    pub fn builder() -> crate::types::builders::ActiveDirectoryConfigBuilder {
        crate::types::builders::ActiveDirectoryConfigBuilder::default()
    }
}

/// A builder for [`ActiveDirectoryConfig`](crate::types::ActiveDirectoryConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActiveDirectoryConfigBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_account_secret_arn: ::std::option::Option<::std::string::String>,
}
impl ActiveDirectoryConfigBuilder {
    /// <p>The name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>Indicates the secret ARN on the service account.</p>
    /// This field is required.
    pub fn service_account_secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_account_secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the secret ARN on the service account.</p>
    pub fn set_service_account_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_account_secret_arn = input;
        self
    }
    /// <p>Indicates the secret ARN on the service account.</p>
    pub fn get_service_account_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_account_secret_arn
    }
    /// Consumes the builder and constructs a [`ActiveDirectoryConfig`](crate::types::ActiveDirectoryConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_name`](crate::types::builders::ActiveDirectoryConfigBuilder::domain_name)
    /// - [`service_account_secret_arn`](crate::types::builders::ActiveDirectoryConfigBuilder::service_account_secret_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::ActiveDirectoryConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ActiveDirectoryConfig {
            domain_name: self.domain_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_name",
                    "domain_name was not specified but it is required when building ActiveDirectoryConfig",
                )
            })?,
            service_account_secret_arn: self.service_account_secret_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_account_secret_arn",
                    "service_account_secret_arn was not specified but it is required when building ActiveDirectoryConfig",
                )
            })?,
        })
    }
}
