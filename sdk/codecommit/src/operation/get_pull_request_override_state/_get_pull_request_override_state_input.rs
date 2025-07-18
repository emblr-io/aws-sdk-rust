// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPullRequestOverrideStateInput {
    /// <p>The ID of the pull request for which you want to get information about whether approval rules have been set aside (overridden).</p>
    pub pull_request_id: ::std::option::Option<::std::string::String>,
    /// <p>The system-generated ID of the revision for the pull request. To retrieve the most recent revision ID, use <code>GetPullRequest</code>.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
}
impl GetPullRequestOverrideStateInput {
    /// <p>The ID of the pull request for which you want to get information about whether approval rules have been set aside (overridden).</p>
    pub fn pull_request_id(&self) -> ::std::option::Option<&str> {
        self.pull_request_id.as_deref()
    }
    /// <p>The system-generated ID of the revision for the pull request. To retrieve the most recent revision ID, use <code>GetPullRequest</code>.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
}
impl GetPullRequestOverrideStateInput {
    /// Creates a new builder-style object to manufacture [`GetPullRequestOverrideStateInput`](crate::operation::get_pull_request_override_state::GetPullRequestOverrideStateInput).
    pub fn builder() -> crate::operation::get_pull_request_override_state::builders::GetPullRequestOverrideStateInputBuilder {
        crate::operation::get_pull_request_override_state::builders::GetPullRequestOverrideStateInputBuilder::default()
    }
}

/// A builder for [`GetPullRequestOverrideStateInput`](crate::operation::get_pull_request_override_state::GetPullRequestOverrideStateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPullRequestOverrideStateInputBuilder {
    pub(crate) pull_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
}
impl GetPullRequestOverrideStateInputBuilder {
    /// <p>The ID of the pull request for which you want to get information about whether approval rules have been set aside (overridden).</p>
    /// This field is required.
    pub fn pull_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pull_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the pull request for which you want to get information about whether approval rules have been set aside (overridden).</p>
    pub fn set_pull_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pull_request_id = input;
        self
    }
    /// <p>The ID of the pull request for which you want to get information about whether approval rules have been set aside (overridden).</p>
    pub fn get_pull_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pull_request_id
    }
    /// <p>The system-generated ID of the revision for the pull request. To retrieve the most recent revision ID, use <code>GetPullRequest</code>.</p>
    /// This field is required.
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated ID of the revision for the pull request. To retrieve the most recent revision ID, use <code>GetPullRequest</code>.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The system-generated ID of the revision for the pull request. To retrieve the most recent revision ID, use <code>GetPullRequest</code>.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// Consumes the builder and constructs a [`GetPullRequestOverrideStateInput`](crate::operation::get_pull_request_override_state::GetPullRequestOverrideStateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_pull_request_override_state::GetPullRequestOverrideStateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_pull_request_override_state::GetPullRequestOverrideStateInput {
            pull_request_id: self.pull_request_id,
            revision_id: self.revision_id,
        })
    }
}
