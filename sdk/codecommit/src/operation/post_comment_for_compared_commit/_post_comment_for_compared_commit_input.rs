// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PostCommentForComparedCommitInput {
    /// <p>The name of the repository where you want to post a comment on the comparison between commits.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>To establish the directionality of the comparison, the full commit ID of the before commit. Required for commenting on any commit unless that commit is the initial commit.</p>
    pub before_commit_id: ::std::option::Option<::std::string::String>,
    /// <p>To establish the directionality of the comparison, the full commit ID of the after commit.</p>
    pub after_commit_id: ::std::option::Option<::std::string::String>,
    /// <p>The location of the comparison where you want to comment.</p>
    pub location: ::std::option::Option<crate::types::Location>,
    /// <p>The content of the comment you want to make.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl PostCommentForComparedCommitInput {
    /// <p>The name of the repository where you want to post a comment on the comparison between commits.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the before commit. Required for commenting on any commit unless that commit is the initial commit.</p>
    pub fn before_commit_id(&self) -> ::std::option::Option<&str> {
        self.before_commit_id.as_deref()
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the after commit.</p>
    pub fn after_commit_id(&self) -> ::std::option::Option<&str> {
        self.after_commit_id.as_deref()
    }
    /// <p>The location of the comparison where you want to comment.</p>
    pub fn location(&self) -> ::std::option::Option<&crate::types::Location> {
        self.location.as_ref()
    }
    /// <p>The content of the comment you want to make.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl PostCommentForComparedCommitInput {
    /// Creates a new builder-style object to manufacture [`PostCommentForComparedCommitInput`](crate::operation::post_comment_for_compared_commit::PostCommentForComparedCommitInput).
    pub fn builder() -> crate::operation::post_comment_for_compared_commit::builders::PostCommentForComparedCommitInputBuilder {
        crate::operation::post_comment_for_compared_commit::builders::PostCommentForComparedCommitInputBuilder::default()
    }
}

/// A builder for [`PostCommentForComparedCommitInput`](crate::operation::post_comment_for_compared_commit::PostCommentForComparedCommitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PostCommentForComparedCommitInputBuilder {
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) before_commit_id: ::std::option::Option<::std::string::String>,
    pub(crate) after_commit_id: ::std::option::Option<::std::string::String>,
    pub(crate) location: ::std::option::Option<crate::types::Location>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl PostCommentForComparedCommitInputBuilder {
    /// <p>The name of the repository where you want to post a comment on the comparison between commits.</p>
    /// This field is required.
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the repository where you want to post a comment on the comparison between commits.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The name of the repository where you want to post a comment on the comparison between commits.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the before commit. Required for commenting on any commit unless that commit is the initial commit.</p>
    pub fn before_commit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.before_commit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the before commit. Required for commenting on any commit unless that commit is the initial commit.</p>
    pub fn set_before_commit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.before_commit_id = input;
        self
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the before commit. Required for commenting on any commit unless that commit is the initial commit.</p>
    pub fn get_before_commit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.before_commit_id
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the after commit.</p>
    /// This field is required.
    pub fn after_commit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.after_commit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the after commit.</p>
    pub fn set_after_commit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.after_commit_id = input;
        self
    }
    /// <p>To establish the directionality of the comparison, the full commit ID of the after commit.</p>
    pub fn get_after_commit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.after_commit_id
    }
    /// <p>The location of the comparison where you want to comment.</p>
    pub fn location(mut self, input: crate::types::Location) -> Self {
        self.location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the comparison where you want to comment.</p>
    pub fn set_location(mut self, input: ::std::option::Option<crate::types::Location>) -> Self {
        self.location = input;
        self
    }
    /// <p>The location of the comparison where you want to comment.</p>
    pub fn get_location(&self) -> &::std::option::Option<crate::types::Location> {
        &self.location
    }
    /// <p>The content of the comment you want to make.</p>
    /// This field is required.
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the comment you want to make.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the comment you want to make.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique, client-generated idempotency token that, when provided in a request, ensures the request cannot be repeated with a changed parameter. If a request is received with the same parameters and a token is included, the request returns information about the initial request that used that token.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`PostCommentForComparedCommitInput`](crate::operation::post_comment_for_compared_commit::PostCommentForComparedCommitInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::post_comment_for_compared_commit::PostCommentForComparedCommitInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::post_comment_for_compared_commit::PostCommentForComparedCommitInput {
            repository_name: self.repository_name,
            before_commit_id: self.before_commit_id,
            after_commit_id: self.after_commit_id,
            location: self.location,
            content: self.content,
            client_request_token: self.client_request_token,
        })
    }
}
