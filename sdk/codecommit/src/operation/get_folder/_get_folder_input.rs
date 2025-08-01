// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFolderInput {
    /// <p>The name of the repository.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>A fully qualified reference used to identify a commit that contains the version of the folder's content to return. A fully qualified reference can be a commit ID, branch name, tag, or reference such as HEAD. If no specifier is provided, the folder content is returned as it exists in the HEAD commit.</p>
    pub commit_specifier: ::std::option::Option<::std::string::String>,
    /// <p>The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.</p>
    pub folder_path: ::std::option::Option<::std::string::String>,
}
impl GetFolderInput {
    /// <p>The name of the repository.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>A fully qualified reference used to identify a commit that contains the version of the folder's content to return. A fully qualified reference can be a commit ID, branch name, tag, or reference such as HEAD. If no specifier is provided, the folder content is returned as it exists in the HEAD commit.</p>
    pub fn commit_specifier(&self) -> ::std::option::Option<&str> {
        self.commit_specifier.as_deref()
    }
    /// <p>The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.</p>
    pub fn folder_path(&self) -> ::std::option::Option<&str> {
        self.folder_path.as_deref()
    }
}
impl GetFolderInput {
    /// Creates a new builder-style object to manufacture [`GetFolderInput`](crate::operation::get_folder::GetFolderInput).
    pub fn builder() -> crate::operation::get_folder::builders::GetFolderInputBuilder {
        crate::operation::get_folder::builders::GetFolderInputBuilder::default()
    }
}

/// A builder for [`GetFolderInput`](crate::operation::get_folder::GetFolderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFolderInputBuilder {
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) commit_specifier: ::std::option::Option<::std::string::String>,
    pub(crate) folder_path: ::std::option::Option<::std::string::String>,
}
impl GetFolderInputBuilder {
    /// <p>The name of the repository.</p>
    /// This field is required.
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>A fully qualified reference used to identify a commit that contains the version of the folder's content to return. A fully qualified reference can be a commit ID, branch name, tag, or reference such as HEAD. If no specifier is provided, the folder content is returned as it exists in the HEAD commit.</p>
    pub fn commit_specifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.commit_specifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A fully qualified reference used to identify a commit that contains the version of the folder's content to return. A fully qualified reference can be a commit ID, branch name, tag, or reference such as HEAD. If no specifier is provided, the folder content is returned as it exists in the HEAD commit.</p>
    pub fn set_commit_specifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.commit_specifier = input;
        self
    }
    /// <p>A fully qualified reference used to identify a commit that contains the version of the folder's content to return. A fully qualified reference can be a commit ID, branch name, tag, or reference such as HEAD. If no specifier is provided, the folder content is returned as it exists in the HEAD commit.</p>
    pub fn get_commit_specifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.commit_specifier
    }
    /// <p>The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.</p>
    /// This field is required.
    pub fn folder_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.folder_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.</p>
    pub fn set_folder_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.folder_path = input;
        self
    }
    /// <p>The fully qualified path to the folder whose contents are returned, including the folder name. For example, /examples is a fully-qualified path to a folder named examples that was created off of the root directory (/) of a repository.</p>
    pub fn get_folder_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.folder_path
    }
    /// Consumes the builder and constructs a [`GetFolderInput`](crate::operation::get_folder::GetFolderInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_folder::GetFolderInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_folder::GetFolderInput {
            repository_name: self.repository_name,
            commit_specifier: self.commit_specifier,
            folder_path: self.folder_path,
        })
    }
}
