// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The repository credentials for private registry authentication.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RepositoryCredentials {
    /// <p>The Amazon Resource Name (ARN) of the secret containing the private repository credentials.</p>
    pub credentials_parameter: ::std::option::Option<::std::string::String>,
}
impl RepositoryCredentials {
    /// <p>The Amazon Resource Name (ARN) of the secret containing the private repository credentials.</p>
    pub fn credentials_parameter(&self) -> ::std::option::Option<&str> {
        self.credentials_parameter.as_deref()
    }
}
impl RepositoryCredentials {
    /// Creates a new builder-style object to manufacture [`RepositoryCredentials`](crate::types::RepositoryCredentials).
    pub fn builder() -> crate::types::builders::RepositoryCredentialsBuilder {
        crate::types::builders::RepositoryCredentialsBuilder::default()
    }
}

/// A builder for [`RepositoryCredentials`](crate::types::RepositoryCredentials).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RepositoryCredentialsBuilder {
    pub(crate) credentials_parameter: ::std::option::Option<::std::string::String>,
}
impl RepositoryCredentialsBuilder {
    /// <p>The Amazon Resource Name (ARN) of the secret containing the private repository credentials.</p>
    /// This field is required.
    pub fn credentials_parameter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.credentials_parameter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the secret containing the private repository credentials.</p>
    pub fn set_credentials_parameter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.credentials_parameter = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the secret containing the private repository credentials.</p>
    pub fn get_credentials_parameter(&self) -> &::std::option::Option<::std::string::String> {
        &self.credentials_parameter
    }
    /// Consumes the builder and constructs a [`RepositoryCredentials`](crate::types::RepositoryCredentials).
    pub fn build(self) -> crate::types::RepositoryCredentials {
        crate::types::RepositoryCredentials {
            credentials_parameter: self.credentials_parameter,
        }
    }
}
