// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateJobFromSourceControlInput {
    /// <p>The name of the Glue job to be synchronized to or from the remote repository.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>The provider for the remote repository. Possible values: GITHUB, AWS_CODE_COMMIT, GITLAB, BITBUCKET.</p>
    pub provider: ::std::option::Option<crate::types::SourceControlProvider>,
    /// <p>The name of the remote repository that contains the job artifacts. For BitBucket providers, <code>RepositoryName</code> should include <code>WorkspaceName</code>. Use the format <code><workspacename>
    /// /
    /// <repositoryname></repositoryname>
    /// </workspacename></code>.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the remote repository that contains the job artifacts.</p>
    pub repository_owner: ::std::option::Option<::std::string::String>,
    /// <p>An optional branch in the remote repository.</p>
    pub branch_name: ::std::option::Option<::std::string::String>,
    /// <p>An optional folder in the remote repository.</p>
    pub folder: ::std::option::Option<::std::string::String>,
    /// <p>A commit ID for a commit in the remote repository.</p>
    pub commit_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of authentication, which can be an authentication token stored in Amazon Web Services Secrets Manager, or a personal access token.</p>
    pub auth_strategy: ::std::option::Option<crate::types::SourceControlAuthStrategy>,
    /// <p>The value of the authorization token.</p>
    pub auth_token: ::std::option::Option<::std::string::String>,
}
impl UpdateJobFromSourceControlInput {
    /// <p>The name of the Glue job to be synchronized to or from the remote repository.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>The provider for the remote repository. Possible values: GITHUB, AWS_CODE_COMMIT, GITLAB, BITBUCKET.</p>
    pub fn provider(&self) -> ::std::option::Option<&crate::types::SourceControlProvider> {
        self.provider.as_ref()
    }
    /// <p>The name of the remote repository that contains the job artifacts. For BitBucket providers, <code>RepositoryName</code> should include <code>WorkspaceName</code>. Use the format <code><workspacename>
    /// /
    /// <repositoryname></repositoryname>
    /// </workspacename></code>.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The owner of the remote repository that contains the job artifacts.</p>
    pub fn repository_owner(&self) -> ::std::option::Option<&str> {
        self.repository_owner.as_deref()
    }
    /// <p>An optional branch in the remote repository.</p>
    pub fn branch_name(&self) -> ::std::option::Option<&str> {
        self.branch_name.as_deref()
    }
    /// <p>An optional folder in the remote repository.</p>
    pub fn folder(&self) -> ::std::option::Option<&str> {
        self.folder.as_deref()
    }
    /// <p>A commit ID for a commit in the remote repository.</p>
    pub fn commit_id(&self) -> ::std::option::Option<&str> {
        self.commit_id.as_deref()
    }
    /// <p>The type of authentication, which can be an authentication token stored in Amazon Web Services Secrets Manager, or a personal access token.</p>
    pub fn auth_strategy(&self) -> ::std::option::Option<&crate::types::SourceControlAuthStrategy> {
        self.auth_strategy.as_ref()
    }
    /// <p>The value of the authorization token.</p>
    pub fn auth_token(&self) -> ::std::option::Option<&str> {
        self.auth_token.as_deref()
    }
}
impl UpdateJobFromSourceControlInput {
    /// Creates a new builder-style object to manufacture [`UpdateJobFromSourceControlInput`](crate::operation::update_job_from_source_control::UpdateJobFromSourceControlInput).
    pub fn builder() -> crate::operation::update_job_from_source_control::builders::UpdateJobFromSourceControlInputBuilder {
        crate::operation::update_job_from_source_control::builders::UpdateJobFromSourceControlInputBuilder::default()
    }
}

/// A builder for [`UpdateJobFromSourceControlInput`](crate::operation::update_job_from_source_control::UpdateJobFromSourceControlInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateJobFromSourceControlInputBuilder {
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) provider: ::std::option::Option<crate::types::SourceControlProvider>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) repository_owner: ::std::option::Option<::std::string::String>,
    pub(crate) branch_name: ::std::option::Option<::std::string::String>,
    pub(crate) folder: ::std::option::Option<::std::string::String>,
    pub(crate) commit_id: ::std::option::Option<::std::string::String>,
    pub(crate) auth_strategy: ::std::option::Option<crate::types::SourceControlAuthStrategy>,
    pub(crate) auth_token: ::std::option::Option<::std::string::String>,
}
impl UpdateJobFromSourceControlInputBuilder {
    /// <p>The name of the Glue job to be synchronized to or from the remote repository.</p>
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Glue job to be synchronized to or from the remote repository.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The name of the Glue job to be synchronized to or from the remote repository.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>The provider for the remote repository. Possible values: GITHUB, AWS_CODE_COMMIT, GITLAB, BITBUCKET.</p>
    pub fn provider(mut self, input: crate::types::SourceControlProvider) -> Self {
        self.provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>The provider for the remote repository. Possible values: GITHUB, AWS_CODE_COMMIT, GITLAB, BITBUCKET.</p>
    pub fn set_provider(mut self, input: ::std::option::Option<crate::types::SourceControlProvider>) -> Self {
        self.provider = input;
        self
    }
    /// <p>The provider for the remote repository. Possible values: GITHUB, AWS_CODE_COMMIT, GITLAB, BITBUCKET.</p>
    pub fn get_provider(&self) -> &::std::option::Option<crate::types::SourceControlProvider> {
        &self.provider
    }
    /// <p>The name of the remote repository that contains the job artifacts. For BitBucket providers, <code>RepositoryName</code> should include <code>WorkspaceName</code>. Use the format <code><workspacename>
    /// /
    /// <repositoryname></repositoryname>
    /// </workspacename></code>.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the remote repository that contains the job artifacts. For BitBucket providers, <code>RepositoryName</code> should include <code>WorkspaceName</code>. Use the format <code><workspacename>
    /// /
    /// <repositoryname></repositoryname>
    /// </workspacename></code>.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the remote repository that contains the job artifacts. For BitBucket providers, <code>RepositoryName</code> should include <code>WorkspaceName</code>. Use the format <code><workspacename>
    /// /
    /// <repositoryname></repositoryname>
    /// </workspacename></code>.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The owner of the remote repository that contains the job artifacts.</p>
    pub fn repository_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the remote repository that contains the job artifacts.</p>
    pub fn set_repository_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_owner = input;
        self
    }
    /// <p>The owner of the remote repository that contains the job artifacts.</p>
    pub fn get_repository_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_owner
    }
    /// <p>An optional branch in the remote repository.</p>
    pub fn branch_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional branch in the remote repository.</p>
    pub fn set_branch_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch_name = input;
        self
    }
    /// <p>An optional branch in the remote repository.</p>
    pub fn get_branch_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch_name
    }
    /// <p>An optional folder in the remote repository.</p>
    pub fn folder(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.folder = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional folder in the remote repository.</p>
    pub fn set_folder(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.folder = input;
        self
    }
    /// <p>An optional folder in the remote repository.</p>
    pub fn get_folder(&self) -> &::std::option::Option<::std::string::String> {
        &self.folder
    }
    /// <p>A commit ID for a commit in the remote repository.</p>
    pub fn commit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.commit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A commit ID for a commit in the remote repository.</p>
    pub fn set_commit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.commit_id = input;
        self
    }
    /// <p>A commit ID for a commit in the remote repository.</p>
    pub fn get_commit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.commit_id
    }
    /// <p>The type of authentication, which can be an authentication token stored in Amazon Web Services Secrets Manager, or a personal access token.</p>
    pub fn auth_strategy(mut self, input: crate::types::SourceControlAuthStrategy) -> Self {
        self.auth_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of authentication, which can be an authentication token stored in Amazon Web Services Secrets Manager, or a personal access token.</p>
    pub fn set_auth_strategy(mut self, input: ::std::option::Option<crate::types::SourceControlAuthStrategy>) -> Self {
        self.auth_strategy = input;
        self
    }
    /// <p>The type of authentication, which can be an authentication token stored in Amazon Web Services Secrets Manager, or a personal access token.</p>
    pub fn get_auth_strategy(&self) -> &::std::option::Option<crate::types::SourceControlAuthStrategy> {
        &self.auth_strategy
    }
    /// <p>The value of the authorization token.</p>
    pub fn auth_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auth_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the authorization token.</p>
    pub fn set_auth_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auth_token = input;
        self
    }
    /// <p>The value of the authorization token.</p>
    pub fn get_auth_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.auth_token
    }
    /// Consumes the builder and constructs a [`UpdateJobFromSourceControlInput`](crate::operation::update_job_from_source_control::UpdateJobFromSourceControlInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_job_from_source_control::UpdateJobFromSourceControlInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_job_from_source_control::UpdateJobFromSourceControlInput {
            job_name: self.job_name,
            provider: self.provider,
            repository_name: self.repository_name,
            repository_owner: self.repository_owner,
            branch_name: self.branch_name,
            folder: self.folder,
            commit_id: self.commit_id,
            auth_strategy: self.auth_strategy,
            auth_token: self.auth_token,
        })
    }
}
