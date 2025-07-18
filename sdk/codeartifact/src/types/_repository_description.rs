// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of a repository stored in CodeArtifact. A CodeArtifact repository contains a set of package versions, each of which maps to a set of assets. Repositories are polyglot—a single repository can contain packages of any supported type. Each repository exposes endpoints for fetching and publishing packages using tools like the <code>npm</code> CLI, the Maven CLI (<code>mvn</code>), and <code>pip</code>. You can create up to 100 repositories per Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RepositoryDescription {
    /// <p>The name of the repository.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The 12-digit account number of the Amazon Web Services account that manages the repository.</p>
    pub administrator_account: ::std::option::Option<::std::string::String>,
    /// <p>The name of the domain that contains the repository.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain that contains the repository. It does not include dashes or spaces.</p>
    pub domain_owner: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the repository.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>A text description of the repository.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of upstream repositories to associate with the repository. The order of the upstream repositories in the list determines their priority order when CodeArtifact looks for a requested package version. For more information, see <a href="https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html">Working with upstream repositories</a>.</p>
    pub upstreams: ::std::option::Option<::std::vec::Vec<crate::types::UpstreamRepositoryInfo>>,
    /// <p>An array of external connections associated with the repository.</p>
    pub external_connections: ::std::option::Option<::std::vec::Vec<crate::types::RepositoryExternalConnectionInfo>>,
    /// <p>A timestamp that represents the date and time the repository was created.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl RepositoryDescription {
    /// <p>The name of the repository.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that manages the repository.</p>
    pub fn administrator_account(&self) -> ::std::option::Option<&str> {
        self.administrator_account.as_deref()
    }
    /// <p>The name of the domain that contains the repository.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain that contains the repository. It does not include dashes or spaces.</p>
    pub fn domain_owner(&self) -> ::std::option::Option<&str> {
        self.domain_owner.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the repository.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>A text description of the repository.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of upstream repositories to associate with the repository. The order of the upstream repositories in the list determines their priority order when CodeArtifact looks for a requested package version. For more information, see <a href="https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html">Working with upstream repositories</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.upstreams.is_none()`.
    pub fn upstreams(&self) -> &[crate::types::UpstreamRepositoryInfo] {
        self.upstreams.as_deref().unwrap_or_default()
    }
    /// <p>An array of external connections associated with the repository.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.external_connections.is_none()`.
    pub fn external_connections(&self) -> &[crate::types::RepositoryExternalConnectionInfo] {
        self.external_connections.as_deref().unwrap_or_default()
    }
    /// <p>A timestamp that represents the date and time the repository was created.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
}
impl RepositoryDescription {
    /// Creates a new builder-style object to manufacture [`RepositoryDescription`](crate::types::RepositoryDescription).
    pub fn builder() -> crate::types::builders::RepositoryDescriptionBuilder {
        crate::types::builders::RepositoryDescriptionBuilder::default()
    }
}

/// A builder for [`RepositoryDescription`](crate::types::RepositoryDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RepositoryDescriptionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) administrator_account: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_owner: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) upstreams: ::std::option::Option<::std::vec::Vec<crate::types::UpstreamRepositoryInfo>>,
    pub(crate) external_connections: ::std::option::Option<::std::vec::Vec<crate::types::RepositoryExternalConnectionInfo>>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl RepositoryDescriptionBuilder {
    /// <p>The name of the repository.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the repository.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that manages the repository.</p>
    pub fn administrator_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.administrator_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that manages the repository.</p>
    pub fn set_administrator_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.administrator_account = input;
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that manages the repository.</p>
    pub fn get_administrator_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.administrator_account
    }
    /// <p>The name of the domain that contains the repository.</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain that contains the repository.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the domain that contains the repository.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain that contains the repository. It does not include dashes or spaces.</p>
    pub fn domain_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain that contains the repository. It does not include dashes or spaces.</p>
    pub fn set_domain_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_owner = input;
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain that contains the repository. It does not include dashes or spaces.</p>
    pub fn get_domain_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_owner
    }
    /// <p>The Amazon Resource Name (ARN) of the repository.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the repository.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the repository.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A text description of the repository.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A text description of the repository.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A text description of the repository.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `upstreams`.
    ///
    /// To override the contents of this collection use [`set_upstreams`](Self::set_upstreams).
    ///
    /// <p>A list of upstream repositories to associate with the repository. The order of the upstream repositories in the list determines their priority order when CodeArtifact looks for a requested package version. For more information, see <a href="https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html">Working with upstream repositories</a>.</p>
    pub fn upstreams(mut self, input: crate::types::UpstreamRepositoryInfo) -> Self {
        let mut v = self.upstreams.unwrap_or_default();
        v.push(input);
        self.upstreams = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of upstream repositories to associate with the repository. The order of the upstream repositories in the list determines their priority order when CodeArtifact looks for a requested package version. For more information, see <a href="https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html">Working with upstream repositories</a>.</p>
    pub fn set_upstreams(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UpstreamRepositoryInfo>>) -> Self {
        self.upstreams = input;
        self
    }
    /// <p>A list of upstream repositories to associate with the repository. The order of the upstream repositories in the list determines their priority order when CodeArtifact looks for a requested package version. For more information, see <a href="https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html">Working with upstream repositories</a>.</p>
    pub fn get_upstreams(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpstreamRepositoryInfo>> {
        &self.upstreams
    }
    /// Appends an item to `external_connections`.
    ///
    /// To override the contents of this collection use [`set_external_connections`](Self::set_external_connections).
    ///
    /// <p>An array of external connections associated with the repository.</p>
    pub fn external_connections(mut self, input: crate::types::RepositoryExternalConnectionInfo) -> Self {
        let mut v = self.external_connections.unwrap_or_default();
        v.push(input);
        self.external_connections = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of external connections associated with the repository.</p>
    pub fn set_external_connections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RepositoryExternalConnectionInfo>>) -> Self {
        self.external_connections = input;
        self
    }
    /// <p>An array of external connections associated with the repository.</p>
    pub fn get_external_connections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RepositoryExternalConnectionInfo>> {
        &self.external_connections
    }
    /// <p>A timestamp that represents the date and time the repository was created.</p>
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that represents the date and time the repository was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>A timestamp that represents the date and time the repository was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// Consumes the builder and constructs a [`RepositoryDescription`](crate::types::RepositoryDescription).
    pub fn build(self) -> crate::types::RepositoryDescription {
        crate::types::RepositoryDescription {
            name: self.name,
            administrator_account: self.administrator_account,
            domain_name: self.domain_name,
            domain_owner: self.domain_owner,
            arn: self.arn,
            description: self.description,
            upstreams: self.upstreams,
            external_connections: self.external_connections,
            created_time: self.created_time,
        }
    }
}
