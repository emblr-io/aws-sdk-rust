// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A source identifier and its corresponding version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProjectSourceVersion {
    /// <p>An identifier for a source in the build project. The identifier can only contain alphanumeric characters and underscores, and must be less than 128 characters in length.</p>
    pub source_identifier: ::std::string::String,
    /// <p>The source version for the corresponding source identifier. If specified, must be one of:</p>
    /// <ul>
    /// <li>
    /// <p>For CodeCommit: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For GitHub: the commit ID, pull request ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a pull request ID is specified, it must use the format <code>pr/pull-request-ID</code> (for example, <code>pr/25</code>). If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For GitLab: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For Bitbucket: the commit ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For Amazon S3: the version ID of the object that represents the build input ZIP file to use.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-source-version.html">Source Version Sample with CodeBuild</a> in the <i>CodeBuild User Guide</i>.</p>
    pub source_version: ::std::string::String,
}
impl ProjectSourceVersion {
    /// <p>An identifier for a source in the build project. The identifier can only contain alphanumeric characters and underscores, and must be less than 128 characters in length.</p>
    pub fn source_identifier(&self) -> &str {
        use std::ops::Deref;
        self.source_identifier.deref()
    }
    /// <p>The source version for the corresponding source identifier. If specified, must be one of:</p>
    /// <ul>
    /// <li>
    /// <p>For CodeCommit: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For GitHub: the commit ID, pull request ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a pull request ID is specified, it must use the format <code>pr/pull-request-ID</code> (for example, <code>pr/25</code>). If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For GitLab: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For Bitbucket: the commit ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For Amazon S3: the version ID of the object that represents the build input ZIP file to use.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-source-version.html">Source Version Sample with CodeBuild</a> in the <i>CodeBuild User Guide</i>.</p>
    pub fn source_version(&self) -> &str {
        use std::ops::Deref;
        self.source_version.deref()
    }
}
impl ProjectSourceVersion {
    /// Creates a new builder-style object to manufacture [`ProjectSourceVersion`](crate::types::ProjectSourceVersion).
    pub fn builder() -> crate::types::builders::ProjectSourceVersionBuilder {
        crate::types::builders::ProjectSourceVersionBuilder::default()
    }
}

/// A builder for [`ProjectSourceVersion`](crate::types::ProjectSourceVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProjectSourceVersionBuilder {
    pub(crate) source_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) source_version: ::std::option::Option<::std::string::String>,
}
impl ProjectSourceVersionBuilder {
    /// <p>An identifier for a source in the build project. The identifier can only contain alphanumeric characters and underscores, and must be less than 128 characters in length.</p>
    /// This field is required.
    pub fn source_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for a source in the build project. The identifier can only contain alphanumeric characters and underscores, and must be less than 128 characters in length.</p>
    pub fn set_source_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_identifier = input;
        self
    }
    /// <p>An identifier for a source in the build project. The identifier can only contain alphanumeric characters and underscores, and must be less than 128 characters in length.</p>
    pub fn get_source_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_identifier
    }
    /// <p>The source version for the corresponding source identifier. If specified, must be one of:</p>
    /// <ul>
    /// <li>
    /// <p>For CodeCommit: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For GitHub: the commit ID, pull request ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a pull request ID is specified, it must use the format <code>pr/pull-request-ID</code> (for example, <code>pr/25</code>). If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For GitLab: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For Bitbucket: the commit ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For Amazon S3: the version ID of the object that represents the build input ZIP file to use.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-source-version.html">Source Version Sample with CodeBuild</a> in the <i>CodeBuild User Guide</i>.</p>
    /// This field is required.
    pub fn source_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source version for the corresponding source identifier. If specified, must be one of:</p>
    /// <ul>
    /// <li>
    /// <p>For CodeCommit: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For GitHub: the commit ID, pull request ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a pull request ID is specified, it must use the format <code>pr/pull-request-ID</code> (for example, <code>pr/25</code>). If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For GitLab: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For Bitbucket: the commit ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For Amazon S3: the version ID of the object that represents the build input ZIP file to use.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-source-version.html">Source Version Sample with CodeBuild</a> in the <i>CodeBuild User Guide</i>.</p>
    pub fn set_source_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_version = input;
        self
    }
    /// <p>The source version for the corresponding source identifier. If specified, must be one of:</p>
    /// <ul>
    /// <li>
    /// <p>For CodeCommit: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For GitHub: the commit ID, pull request ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a pull request ID is specified, it must use the format <code>pr/pull-request-ID</code> (for example, <code>pr/25</code>). If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For GitLab: the commit ID, branch, or Git tag to use.</p></li>
    /// <li>
    /// <p>For Bitbucket: the commit ID, branch name, or tag name that corresponds to the version of the source code you want to build. If a branch name is specified, the branch's HEAD commit ID is used. If not specified, the default branch's HEAD commit ID is used.</p></li>
    /// <li>
    /// <p>For Amazon S3: the version ID of the object that represents the build input ZIP file to use.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/codebuild/latest/userguide/sample-source-version.html">Source Version Sample with CodeBuild</a> in the <i>CodeBuild User Guide</i>.</p>
    pub fn get_source_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_version
    }
    /// Consumes the builder and constructs a [`ProjectSourceVersion`](crate::types::ProjectSourceVersion).
    /// This method will fail if any of the following fields are not set:
    /// - [`source_identifier`](crate::types::builders::ProjectSourceVersionBuilder::source_identifier)
    /// - [`source_version`](crate::types::builders::ProjectSourceVersionBuilder::source_version)
    pub fn build(self) -> ::std::result::Result<crate::types::ProjectSourceVersion, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProjectSourceVersion {
            source_identifier: self.source_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_identifier",
                    "source_identifier was not specified but it is required when building ProjectSourceVersion",
                )
            })?,
            source_version: self.source_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_version",
                    "source_version was not specified but it is required when building ProjectSourceVersion",
                )
            })?,
        })
    }
}
