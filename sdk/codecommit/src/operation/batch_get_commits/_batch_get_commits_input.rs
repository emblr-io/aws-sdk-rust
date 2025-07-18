// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetCommitsInput {
    /// <p>The full commit IDs of the commits to get information about.</p><note>
    /// <p>You must supply the full SHA IDs of each commit. You cannot use shortened SHA IDs.</p>
    /// </note>
    pub commit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the repository that contains the commits.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
}
impl BatchGetCommitsInput {
    /// <p>The full commit IDs of the commits to get information about.</p><note>
    /// <p>You must supply the full SHA IDs of each commit. You cannot use shortened SHA IDs.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.commit_ids.is_none()`.
    pub fn commit_ids(&self) -> &[::std::string::String] {
        self.commit_ids.as_deref().unwrap_or_default()
    }
    /// <p>The name of the repository that contains the commits.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
}
impl BatchGetCommitsInput {
    /// Creates a new builder-style object to manufacture [`BatchGetCommitsInput`](crate::operation::batch_get_commits::BatchGetCommitsInput).
    pub fn builder() -> crate::operation::batch_get_commits::builders::BatchGetCommitsInputBuilder {
        crate::operation::batch_get_commits::builders::BatchGetCommitsInputBuilder::default()
    }
}

/// A builder for [`BatchGetCommitsInput`](crate::operation::batch_get_commits::BatchGetCommitsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetCommitsInputBuilder {
    pub(crate) commit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
}
impl BatchGetCommitsInputBuilder {
    /// Appends an item to `commit_ids`.
    ///
    /// To override the contents of this collection use [`set_commit_ids`](Self::set_commit_ids).
    ///
    /// <p>The full commit IDs of the commits to get information about.</p><note>
    /// <p>You must supply the full SHA IDs of each commit. You cannot use shortened SHA IDs.</p>
    /// </note>
    pub fn commit_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.commit_ids.unwrap_or_default();
        v.push(input.into());
        self.commit_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The full commit IDs of the commits to get information about.</p><note>
    /// <p>You must supply the full SHA IDs of each commit. You cannot use shortened SHA IDs.</p>
    /// </note>
    pub fn set_commit_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.commit_ids = input;
        self
    }
    /// <p>The full commit IDs of the commits to get information about.</p><note>
    /// <p>You must supply the full SHA IDs of each commit. You cannot use shortened SHA IDs.</p>
    /// </note>
    pub fn get_commit_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.commit_ids
    }
    /// <p>The name of the repository that contains the commits.</p>
    /// This field is required.
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository that contains the commits.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository that contains the commits.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// Consumes the builder and constructs a [`BatchGetCommitsInput`](crate::operation::batch_get_commits::BatchGetCommitsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_get_commits::BatchGetCommitsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_get_commits::BatchGetCommitsInput {
            commit_ids: self.commit_ids,
            repository_name: self.repository_name,
        })
    }
}
