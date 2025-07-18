// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about credentials that provide access to a private Docker registry. When this is set:</p>
/// <ul>
/// <li>
/// <p><code>imagePullCredentialsType</code> must be set to <code>SERVICE_ROLE</code>.</p></li>
/// <li>
/// <p>images cannot be curated or an Amazon ECR image.</p></li>
/// </ul>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-private-registry.html">Private Registry with Secrets Manager Sample for CodeBuild</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegistryCredential {
    /// <p>The Amazon Resource Name (ARN) or name of credentials created using Secrets Manager.</p><note>
    /// <p>The <code>credential</code> can use the name of the credentials only if they exist in your current Amazon Web Services Region.</p>
    /// </note>
    pub credential: ::std::string::String,
    /// <p>The service that created the credentials to access a private Docker registry. The valid value, SECRETS_MANAGER, is for Secrets Manager.</p>
    pub credential_provider: crate::types::CredentialProviderType,
}
impl RegistryCredential {
    /// <p>The Amazon Resource Name (ARN) or name of credentials created using Secrets Manager.</p><note>
    /// <p>The <code>credential</code> can use the name of the credentials only if they exist in your current Amazon Web Services Region.</p>
    /// </note>
    pub fn credential(&self) -> &str {
        use std::ops::Deref;
        self.credential.deref()
    }
    /// <p>The service that created the credentials to access a private Docker registry. The valid value, SECRETS_MANAGER, is for Secrets Manager.</p>
    pub fn credential_provider(&self) -> &crate::types::CredentialProviderType {
        &self.credential_provider
    }
}
impl RegistryCredential {
    /// Creates a new builder-style object to manufacture [`RegistryCredential`](crate::types::RegistryCredential).
    pub fn builder() -> crate::types::builders::RegistryCredentialBuilder {
        crate::types::builders::RegistryCredentialBuilder::default()
    }
}

/// A builder for [`RegistryCredential`](crate::types::RegistryCredential).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegistryCredentialBuilder {
    pub(crate) credential: ::std::option::Option<::std::string::String>,
    pub(crate) credential_provider: ::std::option::Option<crate::types::CredentialProviderType>,
}
impl RegistryCredentialBuilder {
    /// <p>The Amazon Resource Name (ARN) or name of credentials created using Secrets Manager.</p><note>
    /// <p>The <code>credential</code> can use the name of the credentials only if they exist in your current Amazon Web Services Region.</p>
    /// </note>
    /// This field is required.
    pub fn credential(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.credential = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or name of credentials created using Secrets Manager.</p><note>
    /// <p>The <code>credential</code> can use the name of the credentials only if they exist in your current Amazon Web Services Region.</p>
    /// </note>
    pub fn set_credential(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.credential = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or name of credentials created using Secrets Manager.</p><note>
    /// <p>The <code>credential</code> can use the name of the credentials only if they exist in your current Amazon Web Services Region.</p>
    /// </note>
    pub fn get_credential(&self) -> &::std::option::Option<::std::string::String> {
        &self.credential
    }
    /// <p>The service that created the credentials to access a private Docker registry. The valid value, SECRETS_MANAGER, is for Secrets Manager.</p>
    /// This field is required.
    pub fn credential_provider(mut self, input: crate::types::CredentialProviderType) -> Self {
        self.credential_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>The service that created the credentials to access a private Docker registry. The valid value, SECRETS_MANAGER, is for Secrets Manager.</p>
    pub fn set_credential_provider(mut self, input: ::std::option::Option<crate::types::CredentialProviderType>) -> Self {
        self.credential_provider = input;
        self
    }
    /// <p>The service that created the credentials to access a private Docker registry. The valid value, SECRETS_MANAGER, is for Secrets Manager.</p>
    pub fn get_credential_provider(&self) -> &::std::option::Option<crate::types::CredentialProviderType> {
        &self.credential_provider
    }
    /// Consumes the builder and constructs a [`RegistryCredential`](crate::types::RegistryCredential).
    /// This method will fail if any of the following fields are not set:
    /// - [`credential`](crate::types::builders::RegistryCredentialBuilder::credential)
    /// - [`credential_provider`](crate::types::builders::RegistryCredentialBuilder::credential_provider)
    pub fn build(self) -> ::std::result::Result<crate::types::RegistryCredential, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RegistryCredential {
            credential: self.credential.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "credential",
                    "credential was not specified but it is required when building RegistryCredential",
                )
            })?,
            credential_provider: self.credential_provider.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "credential_provider",
                    "credential_provider was not specified but it is required when building RegistryCredential",
                )
            })?,
        })
    }
}
