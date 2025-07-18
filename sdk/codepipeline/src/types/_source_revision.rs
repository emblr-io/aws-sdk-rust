// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the version (or revision) of a source artifact that initiated a pipeline execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceRevision {
    /// <p>The name of the action that processed the revision to the source artifact.</p>
    pub action_name: ::std::string::String,
    /// <p>The system-generated unique ID that identifies the revision number of the artifact.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>Summary information about the most recent revision of the artifact. For GitHub and CodeCommit repositories, the commit message. For Amazon S3 buckets or actions, the user-provided content of a <code>codepipeline-artifact-revision-summary</code> key specified in the object metadata.</p>
    pub revision_summary: ::std::option::Option<::std::string::String>,
    /// <p>The commit ID for the artifact revision. For artifacts stored in GitHub or CodeCommit repositories, the commit ID is linked to a commit details page.</p>
    pub revision_url: ::std::option::Option<::std::string::String>,
}
impl SourceRevision {
    /// <p>The name of the action that processed the revision to the source artifact.</p>
    pub fn action_name(&self) -> &str {
        use std::ops::Deref;
        self.action_name.deref()
    }
    /// <p>The system-generated unique ID that identifies the revision number of the artifact.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>Summary information about the most recent revision of the artifact. For GitHub and CodeCommit repositories, the commit message. For Amazon S3 buckets or actions, the user-provided content of a <code>codepipeline-artifact-revision-summary</code> key specified in the object metadata.</p>
    pub fn revision_summary(&self) -> ::std::option::Option<&str> {
        self.revision_summary.as_deref()
    }
    /// <p>The commit ID for the artifact revision. For artifacts stored in GitHub or CodeCommit repositories, the commit ID is linked to a commit details page.</p>
    pub fn revision_url(&self) -> ::std::option::Option<&str> {
        self.revision_url.as_deref()
    }
}
impl SourceRevision {
    /// Creates a new builder-style object to manufacture [`SourceRevision`](crate::types::SourceRevision).
    pub fn builder() -> crate::types::builders::SourceRevisionBuilder {
        crate::types::builders::SourceRevisionBuilder::default()
    }
}

/// A builder for [`SourceRevision`](crate::types::SourceRevision).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceRevisionBuilder {
    pub(crate) action_name: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) revision_summary: ::std::option::Option<::std::string::String>,
    pub(crate) revision_url: ::std::option::Option<::std::string::String>,
}
impl SourceRevisionBuilder {
    /// <p>The name of the action that processed the revision to the source artifact.</p>
    /// This field is required.
    pub fn action_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the action that processed the revision to the source artifact.</p>
    pub fn set_action_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_name = input;
        self
    }
    /// <p>The name of the action that processed the revision to the source artifact.</p>
    pub fn get_action_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_name
    }
    /// <p>The system-generated unique ID that identifies the revision number of the artifact.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated unique ID that identifies the revision number of the artifact.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The system-generated unique ID that identifies the revision number of the artifact.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>Summary information about the most recent revision of the artifact. For GitHub and CodeCommit repositories, the commit message. For Amazon S3 buckets or actions, the user-provided content of a <code>codepipeline-artifact-revision-summary</code> key specified in the object metadata.</p>
    pub fn revision_summary(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_summary = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Summary information about the most recent revision of the artifact. For GitHub and CodeCommit repositories, the commit message. For Amazon S3 buckets or actions, the user-provided content of a <code>codepipeline-artifact-revision-summary</code> key specified in the object metadata.</p>
    pub fn set_revision_summary(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_summary = input;
        self
    }
    /// <p>Summary information about the most recent revision of the artifact. For GitHub and CodeCommit repositories, the commit message. For Amazon S3 buckets or actions, the user-provided content of a <code>codepipeline-artifact-revision-summary</code> key specified in the object metadata.</p>
    pub fn get_revision_summary(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_summary
    }
    /// <p>The commit ID for the artifact revision. For artifacts stored in GitHub or CodeCommit repositories, the commit ID is linked to a commit details page.</p>
    pub fn revision_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The commit ID for the artifact revision. For artifacts stored in GitHub or CodeCommit repositories, the commit ID is linked to a commit details page.</p>
    pub fn set_revision_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_url = input;
        self
    }
    /// <p>The commit ID for the artifact revision. For artifacts stored in GitHub or CodeCommit repositories, the commit ID is linked to a commit details page.</p>
    pub fn get_revision_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_url
    }
    /// Consumes the builder and constructs a [`SourceRevision`](crate::types::SourceRevision).
    /// This method will fail if any of the following fields are not set:
    /// - [`action_name`](crate::types::builders::SourceRevisionBuilder::action_name)
    pub fn build(self) -> ::std::result::Result<crate::types::SourceRevision, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SourceRevision {
            action_name: self.action_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action_name",
                    "action_name was not specified but it is required when building SourceRevision",
                )
            })?,
            revision_id: self.revision_id,
            revision_summary: self.revision_summary,
            revision_url: self.revision_url,
        })
    }
}
