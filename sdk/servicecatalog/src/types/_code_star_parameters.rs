// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The subtype containing details about the Codestar connection <code>Type</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeStarParameters {
    /// <p>The CodeStar ARN, which is the connection between Service Catalog and the external repository.</p>
    pub connection_arn: ::std::string::String,
    /// <p>The specific repository where the product’s artifact-to-be-synced resides, formatted as "Account/Repo."</p>
    pub repository: ::std::string::String,
    /// <p>The specific branch where the artifact resides.</p>
    pub branch: ::std::string::String,
    /// <p>The absolute path wehre the artifact resides within the repo and branch, formatted as "folder/file.json."</p>
    pub artifact_path: ::std::string::String,
}
impl CodeStarParameters {
    /// <p>The CodeStar ARN, which is the connection between Service Catalog and the external repository.</p>
    pub fn connection_arn(&self) -> &str {
        use std::ops::Deref;
        self.connection_arn.deref()
    }
    /// <p>The specific repository where the product’s artifact-to-be-synced resides, formatted as "Account/Repo."</p>
    pub fn repository(&self) -> &str {
        use std::ops::Deref;
        self.repository.deref()
    }
    /// <p>The specific branch where the artifact resides.</p>
    pub fn branch(&self) -> &str {
        use std::ops::Deref;
        self.branch.deref()
    }
    /// <p>The absolute path wehre the artifact resides within the repo and branch, formatted as "folder/file.json."</p>
    pub fn artifact_path(&self) -> &str {
        use std::ops::Deref;
        self.artifact_path.deref()
    }
}
impl CodeStarParameters {
    /// Creates a new builder-style object to manufacture [`CodeStarParameters`](crate::types::CodeStarParameters).
    pub fn builder() -> crate::types::builders::CodeStarParametersBuilder {
        crate::types::builders::CodeStarParametersBuilder::default()
    }
}

/// A builder for [`CodeStarParameters`](crate::types::CodeStarParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeStarParametersBuilder {
    pub(crate) connection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) repository: ::std::option::Option<::std::string::String>,
    pub(crate) branch: ::std::option::Option<::std::string::String>,
    pub(crate) artifact_path: ::std::option::Option<::std::string::String>,
}
impl CodeStarParametersBuilder {
    /// <p>The CodeStar ARN, which is the connection between Service Catalog and the external repository.</p>
    /// This field is required.
    pub fn connection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CodeStar ARN, which is the connection between Service Catalog and the external repository.</p>
    pub fn set_connection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_arn = input;
        self
    }
    /// <p>The CodeStar ARN, which is the connection between Service Catalog and the external repository.</p>
    pub fn get_connection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_arn
    }
    /// <p>The specific repository where the product’s artifact-to-be-synced resides, formatted as "Account/Repo."</p>
    /// This field is required.
    pub fn repository(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The specific repository where the product’s artifact-to-be-synced resides, formatted as "Account/Repo."</p>
    pub fn set_repository(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository = input;
        self
    }
    /// <p>The specific repository where the product’s artifact-to-be-synced resides, formatted as "Account/Repo."</p>
    pub fn get_repository(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository
    }
    /// <p>The specific branch where the artifact resides.</p>
    /// This field is required.
    pub fn branch(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The specific branch where the artifact resides.</p>
    pub fn set_branch(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch = input;
        self
    }
    /// <p>The specific branch where the artifact resides.</p>
    pub fn get_branch(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch
    }
    /// <p>The absolute path wehre the artifact resides within the repo and branch, formatted as "folder/file.json."</p>
    /// This field is required.
    pub fn artifact_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.artifact_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The absolute path wehre the artifact resides within the repo and branch, formatted as "folder/file.json."</p>
    pub fn set_artifact_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.artifact_path = input;
        self
    }
    /// <p>The absolute path wehre the artifact resides within the repo and branch, formatted as "folder/file.json."</p>
    pub fn get_artifact_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.artifact_path
    }
    /// Consumes the builder and constructs a [`CodeStarParameters`](crate::types::CodeStarParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`connection_arn`](crate::types::builders::CodeStarParametersBuilder::connection_arn)
    /// - [`repository`](crate::types::builders::CodeStarParametersBuilder::repository)
    /// - [`branch`](crate::types::builders::CodeStarParametersBuilder::branch)
    /// - [`artifact_path`](crate::types::builders::CodeStarParametersBuilder::artifact_path)
    pub fn build(self) -> ::std::result::Result<crate::types::CodeStarParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CodeStarParameters {
            connection_arn: self.connection_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connection_arn",
                    "connection_arn was not specified but it is required when building CodeStarParameters",
                )
            })?,
            repository: self.repository.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "repository",
                    "repository was not specified but it is required when building CodeStarParameters",
                )
            })?,
            branch: self.branch.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "branch",
                    "branch was not specified but it is required when building CodeStarParameters",
                )
            })?,
            artifact_path: self.artifact_path.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "artifact_path",
                    "artifact_path was not specified but it is required when building CodeStarParameters",
                )
            })?,
        })
    }
}
