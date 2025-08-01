// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about how a package originally entered the CodeArtifact domain. For packages published directly to CodeArtifact, the entry point is the repository it was published to. For packages ingested from an external repository, the entry point is the external connection that it was ingested from. An external connection is a CodeArtifact repository that is connected to an external repository such as the npm registry or NuGet gallery.</p><note>
/// <p>If a package version exists in a repository and is updated, for example if a package of the same version is added with additional assets, the package version's <code>DomainEntryPoint</code> will not change from the original package version's value.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainEntryPoint {
    /// <p>The name of the repository that a package was originally published to.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the external connection that a package was ingested from.</p>
    pub external_connection_name: ::std::option::Option<::std::string::String>,
}
impl DomainEntryPoint {
    /// <p>The name of the repository that a package was originally published to.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The name of the external connection that a package was ingested from.</p>
    pub fn external_connection_name(&self) -> ::std::option::Option<&str> {
        self.external_connection_name.as_deref()
    }
}
impl DomainEntryPoint {
    /// Creates a new builder-style object to manufacture [`DomainEntryPoint`](crate::types::DomainEntryPoint).
    pub fn builder() -> crate::types::builders::DomainEntryPointBuilder {
        crate::types::builders::DomainEntryPointBuilder::default()
    }
}

/// A builder for [`DomainEntryPoint`](crate::types::DomainEntryPoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainEntryPointBuilder {
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) external_connection_name: ::std::option::Option<::std::string::String>,
}
impl DomainEntryPointBuilder {
    /// <p>The name of the repository that a package was originally published to.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository that a package was originally published to.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository that a package was originally published to.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The name of the external connection that a package was ingested from.</p>
    pub fn external_connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the external connection that a package was ingested from.</p>
    pub fn set_external_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_connection_name = input;
        self
    }
    /// <p>The name of the external connection that a package was ingested from.</p>
    pub fn get_external_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_connection_name
    }
    /// Consumes the builder and constructs a [`DomainEntryPoint`](crate::types::DomainEntryPoint).
    pub fn build(self) -> crate::types::DomainEntryPoint {
        crate::types::DomainEntryPoint {
            repository_name: self.repository_name,
            external_connection_name: self.external_connection_name,
        }
    }
}
