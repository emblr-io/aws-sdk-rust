// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about a repository association. The <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a> operation returns a list of <code>RepositoryAssociationSummary</code> objects.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RepositoryAssociationSummary {
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_RepositoryAssociation.html">RepositoryAssociation</a> object. You can retrieve this ARN by calling <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a>.</p>
    pub association_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of an Amazon Web Services CodeStar Connections connection. Its format is <code>arn:aws:codestar-connections:region-id:aws-account_id:connection/connection-id</code>. For more information, see <a href="https://docs.aws.amazon.com/codestar-connections/latest/APIReference/API_Connection.html">Connection</a> in the <i>Amazon Web Services CodeStar Connections API Reference</i>.</p>
    pub connection_arn: ::std::option::Option<::std::string::String>,
    /// <p>The time, in milliseconds since the epoch, since the repository association was last updated.</p>
    pub last_updated_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The repository association ID.</p>
    pub association_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the repository association.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The provider type of the repository association.</p>
    pub provider_type: ::std::option::Option<crate::types::ProviderType>,
    /// <p>The state of the repository association.</p>
    /// <p>The valid repository association states are:</p>
    /// <ul>
    /// <li>
    /// <p><b>Associated</b>: The repository association is complete.</p></li>
    /// <li>
    /// <p><b>Associating</b>: CodeGuru Reviewer is:</p>
    /// <ul>
    /// <li>
    /// <p>Setting up pull request notifications. This is required for pull requests to trigger a CodeGuru Reviewer review.</p><note>
    /// <p>If your repository <code>ProviderType</code> is <code>GitHub</code>, <code>GitHub Enterprise Server</code>, or <code>Bitbucket</code>, CodeGuru Reviewer creates webhooks in your repository to trigger CodeGuru Reviewer reviews. If you delete these webhooks, reviews of code in your repository cannot be triggered.</p>
    /// </note></li>
    /// <li>
    /// <p>Setting up source code access. This is required for CodeGuru Reviewer to securely clone code in your repository.</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Failed</b>: The repository failed to associate or disassociate.</p></li>
    /// <li>
    /// <p><b>Disassociating</b>: CodeGuru Reviewer is removing the repository's pull request notifications and source code access.</p></li>
    /// <li>
    /// <p><b>Disassociated</b>: CodeGuru Reviewer successfully disassociated the repository. You can create a new association with this repository if you want to review source code in it later. You can control access to code reviews created in anassociated repository with tags after it has been disassociated. For more information, see <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/auth-and-access-control-using-tags.html">Using tags to control access to associated repositories</a> in the <i>Amazon CodeGuru Reviewer User Guide</i>.</p></li>
    /// </ul>
    pub state: ::std::option::Option<crate::types::RepositoryAssociationState>,
}
impl RepositoryAssociationSummary {
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_RepositoryAssociation.html">RepositoryAssociation</a> object. You can retrieve this ARN by calling <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a>.</p>
    pub fn association_arn(&self) -> ::std::option::Option<&str> {
        self.association_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon Web Services CodeStar Connections connection. Its format is <code>arn:aws:codestar-connections:region-id:aws-account_id:connection/connection-id</code>. For more information, see <a href="https://docs.aws.amazon.com/codestar-connections/latest/APIReference/API_Connection.html">Connection</a> in the <i>Amazon Web Services CodeStar Connections API Reference</i>.</p>
    pub fn connection_arn(&self) -> ::std::option::Option<&str> {
        self.connection_arn.as_deref()
    }
    /// <p>The time, in milliseconds since the epoch, since the repository association was last updated.</p>
    pub fn last_updated_time_stamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time_stamp.as_ref()
    }
    /// <p>The repository association ID.</p>
    pub fn association_id(&self) -> ::std::option::Option<&str> {
        self.association_id.as_deref()
    }
    /// <p>The name of the repository association.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The provider type of the repository association.</p>
    pub fn provider_type(&self) -> ::std::option::Option<&crate::types::ProviderType> {
        self.provider_type.as_ref()
    }
    /// <p>The state of the repository association.</p>
    /// <p>The valid repository association states are:</p>
    /// <ul>
    /// <li>
    /// <p><b>Associated</b>: The repository association is complete.</p></li>
    /// <li>
    /// <p><b>Associating</b>: CodeGuru Reviewer is:</p>
    /// <ul>
    /// <li>
    /// <p>Setting up pull request notifications. This is required for pull requests to trigger a CodeGuru Reviewer review.</p><note>
    /// <p>If your repository <code>ProviderType</code> is <code>GitHub</code>, <code>GitHub Enterprise Server</code>, or <code>Bitbucket</code>, CodeGuru Reviewer creates webhooks in your repository to trigger CodeGuru Reviewer reviews. If you delete these webhooks, reviews of code in your repository cannot be triggered.</p>
    /// </note></li>
    /// <li>
    /// <p>Setting up source code access. This is required for CodeGuru Reviewer to securely clone code in your repository.</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Failed</b>: The repository failed to associate or disassociate.</p></li>
    /// <li>
    /// <p><b>Disassociating</b>: CodeGuru Reviewer is removing the repository's pull request notifications and source code access.</p></li>
    /// <li>
    /// <p><b>Disassociated</b>: CodeGuru Reviewer successfully disassociated the repository. You can create a new association with this repository if you want to review source code in it later. You can control access to code reviews created in anassociated repository with tags after it has been disassociated. For more information, see <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/auth-and-access-control-using-tags.html">Using tags to control access to associated repositories</a> in the <i>Amazon CodeGuru Reviewer User Guide</i>.</p></li>
    /// </ul>
    pub fn state(&self) -> ::std::option::Option<&crate::types::RepositoryAssociationState> {
        self.state.as_ref()
    }
}
impl RepositoryAssociationSummary {
    /// Creates a new builder-style object to manufacture [`RepositoryAssociationSummary`](crate::types::RepositoryAssociationSummary).
    pub fn builder() -> crate::types::builders::RepositoryAssociationSummaryBuilder {
        crate::types::builders::RepositoryAssociationSummaryBuilder::default()
    }
}

/// A builder for [`RepositoryAssociationSummary`](crate::types::RepositoryAssociationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RepositoryAssociationSummaryBuilder {
    pub(crate) association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) connection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_time_stamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) association_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) provider_type: ::std::option::Option<crate::types::ProviderType>,
    pub(crate) state: ::std::option::Option<crate::types::RepositoryAssociationState>,
}
impl RepositoryAssociationSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_RepositoryAssociation.html">RepositoryAssociation</a> object. You can retrieve this ARN by calling <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a>.</p>
    pub fn association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_RepositoryAssociation.html">RepositoryAssociation</a> object. You can retrieve this ARN by calling <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a>.</p>
    pub fn set_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_RepositoryAssociation.html">RepositoryAssociation</a> object. You can retrieve this ARN by calling <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-api/API_ListRepositoryAssociations.html">ListRepositoryAssociations</a>.</p>
    pub fn get_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_arn
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon Web Services CodeStar Connections connection. Its format is <code>arn:aws:codestar-connections:region-id:aws-account_id:connection/connection-id</code>. For more information, see <a href="https://docs.aws.amazon.com/codestar-connections/latest/APIReference/API_Connection.html">Connection</a> in the <i>Amazon Web Services CodeStar Connections API Reference</i>.</p>
    pub fn connection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon Web Services CodeStar Connections connection. Its format is <code>arn:aws:codestar-connections:region-id:aws-account_id:connection/connection-id</code>. For more information, see <a href="https://docs.aws.amazon.com/codestar-connections/latest/APIReference/API_Connection.html">Connection</a> in the <i>Amazon Web Services CodeStar Connections API Reference</i>.</p>
    pub fn set_connection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon Web Services CodeStar Connections connection. Its format is <code>arn:aws:codestar-connections:region-id:aws-account_id:connection/connection-id</code>. For more information, see <a href="https://docs.aws.amazon.com/codestar-connections/latest/APIReference/API_Connection.html">Connection</a> in the <i>Amazon Web Services CodeStar Connections API Reference</i>.</p>
    pub fn get_connection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_arn
    }
    /// <p>The time, in milliseconds since the epoch, since the repository association was last updated.</p>
    pub fn last_updated_time_stamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time_stamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, since the repository association was last updated.</p>
    pub fn set_last_updated_time_stamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time_stamp = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, since the repository association was last updated.</p>
    pub fn get_last_updated_time_stamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time_stamp
    }
    /// <p>The repository association ID.</p>
    pub fn association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The repository association ID.</p>
    pub fn set_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_id = input;
        self
    }
    /// <p>The repository association ID.</p>
    pub fn get_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_id
    }
    /// <p>The name of the repository association.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository association.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the repository association.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the repository. For an Amazon Web Services CodeCommit repository, this is the Amazon Web Services account ID of the account that owns the repository. For a GitHub, GitHub Enterprise Server, or Bitbucket repository, this is the username for the account that owns the repository. For an S3 repository, it can be the username or Amazon Web Services account ID.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The provider type of the repository association.</p>
    pub fn provider_type(mut self, input: crate::types::ProviderType) -> Self {
        self.provider_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The provider type of the repository association.</p>
    pub fn set_provider_type(mut self, input: ::std::option::Option<crate::types::ProviderType>) -> Self {
        self.provider_type = input;
        self
    }
    /// <p>The provider type of the repository association.</p>
    pub fn get_provider_type(&self) -> &::std::option::Option<crate::types::ProviderType> {
        &self.provider_type
    }
    /// <p>The state of the repository association.</p>
    /// <p>The valid repository association states are:</p>
    /// <ul>
    /// <li>
    /// <p><b>Associated</b>: The repository association is complete.</p></li>
    /// <li>
    /// <p><b>Associating</b>: CodeGuru Reviewer is:</p>
    /// <ul>
    /// <li>
    /// <p>Setting up pull request notifications. This is required for pull requests to trigger a CodeGuru Reviewer review.</p><note>
    /// <p>If your repository <code>ProviderType</code> is <code>GitHub</code>, <code>GitHub Enterprise Server</code>, or <code>Bitbucket</code>, CodeGuru Reviewer creates webhooks in your repository to trigger CodeGuru Reviewer reviews. If you delete these webhooks, reviews of code in your repository cannot be triggered.</p>
    /// </note></li>
    /// <li>
    /// <p>Setting up source code access. This is required for CodeGuru Reviewer to securely clone code in your repository.</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Failed</b>: The repository failed to associate or disassociate.</p></li>
    /// <li>
    /// <p><b>Disassociating</b>: CodeGuru Reviewer is removing the repository's pull request notifications and source code access.</p></li>
    /// <li>
    /// <p><b>Disassociated</b>: CodeGuru Reviewer successfully disassociated the repository. You can create a new association with this repository if you want to review source code in it later. You can control access to code reviews created in anassociated repository with tags after it has been disassociated. For more information, see <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/auth-and-access-control-using-tags.html">Using tags to control access to associated repositories</a> in the <i>Amazon CodeGuru Reviewer User Guide</i>.</p></li>
    /// </ul>
    pub fn state(mut self, input: crate::types::RepositoryAssociationState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the repository association.</p>
    /// <p>The valid repository association states are:</p>
    /// <ul>
    /// <li>
    /// <p><b>Associated</b>: The repository association is complete.</p></li>
    /// <li>
    /// <p><b>Associating</b>: CodeGuru Reviewer is:</p>
    /// <ul>
    /// <li>
    /// <p>Setting up pull request notifications. This is required for pull requests to trigger a CodeGuru Reviewer review.</p><note>
    /// <p>If your repository <code>ProviderType</code> is <code>GitHub</code>, <code>GitHub Enterprise Server</code>, or <code>Bitbucket</code>, CodeGuru Reviewer creates webhooks in your repository to trigger CodeGuru Reviewer reviews. If you delete these webhooks, reviews of code in your repository cannot be triggered.</p>
    /// </note></li>
    /// <li>
    /// <p>Setting up source code access. This is required for CodeGuru Reviewer to securely clone code in your repository.</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Failed</b>: The repository failed to associate or disassociate.</p></li>
    /// <li>
    /// <p><b>Disassociating</b>: CodeGuru Reviewer is removing the repository's pull request notifications and source code access.</p></li>
    /// <li>
    /// <p><b>Disassociated</b>: CodeGuru Reviewer successfully disassociated the repository. You can create a new association with this repository if you want to review source code in it later. You can control access to code reviews created in anassociated repository with tags after it has been disassociated. For more information, see <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/auth-and-access-control-using-tags.html">Using tags to control access to associated repositories</a> in the <i>Amazon CodeGuru Reviewer User Guide</i>.</p></li>
    /// </ul>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::RepositoryAssociationState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the repository association.</p>
    /// <p>The valid repository association states are:</p>
    /// <ul>
    /// <li>
    /// <p><b>Associated</b>: The repository association is complete.</p></li>
    /// <li>
    /// <p><b>Associating</b>: CodeGuru Reviewer is:</p>
    /// <ul>
    /// <li>
    /// <p>Setting up pull request notifications. This is required for pull requests to trigger a CodeGuru Reviewer review.</p><note>
    /// <p>If your repository <code>ProviderType</code> is <code>GitHub</code>, <code>GitHub Enterprise Server</code>, or <code>Bitbucket</code>, CodeGuru Reviewer creates webhooks in your repository to trigger CodeGuru Reviewer reviews. If you delete these webhooks, reviews of code in your repository cannot be triggered.</p>
    /// </note></li>
    /// <li>
    /// <p>Setting up source code access. This is required for CodeGuru Reviewer to securely clone code in your repository.</p></li>
    /// </ul></li>
    /// <li>
    /// <p><b>Failed</b>: The repository failed to associate or disassociate.</p></li>
    /// <li>
    /// <p><b>Disassociating</b>: CodeGuru Reviewer is removing the repository's pull request notifications and source code access.</p></li>
    /// <li>
    /// <p><b>Disassociated</b>: CodeGuru Reviewer successfully disassociated the repository. You can create a new association with this repository if you want to review source code in it later. You can control access to code reviews created in anassociated repository with tags after it has been disassociated. For more information, see <a href="https://docs.aws.amazon.com/codeguru/latest/reviewer-ug/auth-and-access-control-using-tags.html">Using tags to control access to associated repositories</a> in the <i>Amazon CodeGuru Reviewer User Guide</i>.</p></li>
    /// </ul>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::RepositoryAssociationState> {
        &self.state
    }
    /// Consumes the builder and constructs a [`RepositoryAssociationSummary`](crate::types::RepositoryAssociationSummary).
    pub fn build(self) -> crate::types::RepositoryAssociationSummary {
        crate::types::RepositoryAssociationSummary {
            association_arn: self.association_arn,
            connection_arn: self.connection_arn,
            last_updated_time_stamp: self.last_updated_time_stamp,
            association_id: self.association_id,
            name: self.name,
            owner: self.owner,
            provider_type: self.provider_type,
            state: self.state,
        }
    }
}
