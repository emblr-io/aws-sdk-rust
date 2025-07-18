// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a comment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Comment {
    /// <p>The ID of the comment.</p>
    pub comment_id: ::std::string::String,
    /// <p>The ID of the parent comment.</p>
    pub parent_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the root comment in the thread.</p>
    pub thread_id: ::std::option::Option<::std::string::String>,
    /// <p>The text of the comment.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>The details of the user who made the comment.</p>
    pub contributor: ::std::option::Option<crate::types::User>,
    /// <p>The time that the comment was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the comment.</p>
    pub status: ::std::option::Option<crate::types::CommentStatusType>,
    /// <p>The visibility of the comment. Options are either PRIVATE, where the comment is visible only to the comment author and document owner and co-owners, or PUBLIC, where the comment is visible to document owners, co-owners, and contributors.</p>
    pub visibility: ::std::option::Option<crate::types::CommentVisibilityType>,
    /// <p>If the comment is a reply to another user's comment, this field contains the user ID of the user being replied to.</p>
    pub recipient_id: ::std::option::Option<::std::string::String>,
}
impl Comment {
    /// <p>The ID of the comment.</p>
    pub fn comment_id(&self) -> &str {
        use std::ops::Deref;
        self.comment_id.deref()
    }
    /// <p>The ID of the parent comment.</p>
    pub fn parent_id(&self) -> ::std::option::Option<&str> {
        self.parent_id.as_deref()
    }
    /// <p>The ID of the root comment in the thread.</p>
    pub fn thread_id(&self) -> ::std::option::Option<&str> {
        self.thread_id.as_deref()
    }
    /// <p>The text of the comment.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>The details of the user who made the comment.</p>
    pub fn contributor(&self) -> ::std::option::Option<&crate::types::User> {
        self.contributor.as_ref()
    }
    /// <p>The time that the comment was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The status of the comment.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::CommentStatusType> {
        self.status.as_ref()
    }
    /// <p>The visibility of the comment. Options are either PRIVATE, where the comment is visible only to the comment author and document owner and co-owners, or PUBLIC, where the comment is visible to document owners, co-owners, and contributors.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::CommentVisibilityType> {
        self.visibility.as_ref()
    }
    /// <p>If the comment is a reply to another user's comment, this field contains the user ID of the user being replied to.</p>
    pub fn recipient_id(&self) -> ::std::option::Option<&str> {
        self.recipient_id.as_deref()
    }
}
impl ::std::fmt::Debug for Comment {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Comment");
        formatter.field("comment_id", &self.comment_id);
        formatter.field("parent_id", &self.parent_id);
        formatter.field("thread_id", &self.thread_id);
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("contributor", &self.contributor);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("status", &self.status);
        formatter.field("visibility", &self.visibility);
        formatter.field("recipient_id", &self.recipient_id);
        formatter.finish()
    }
}
impl Comment {
    /// Creates a new builder-style object to manufacture [`Comment`](crate::types::Comment).
    pub fn builder() -> crate::types::builders::CommentBuilder {
        crate::types::builders::CommentBuilder::default()
    }
}

/// A builder for [`Comment`](crate::types::Comment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CommentBuilder {
    pub(crate) comment_id: ::std::option::Option<::std::string::String>,
    pub(crate) parent_id: ::std::option::Option<::std::string::String>,
    pub(crate) thread_id: ::std::option::Option<::std::string::String>,
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) contributor: ::std::option::Option<crate::types::User>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::CommentStatusType>,
    pub(crate) visibility: ::std::option::Option<crate::types::CommentVisibilityType>,
    pub(crate) recipient_id: ::std::option::Option<::std::string::String>,
}
impl CommentBuilder {
    /// <p>The ID of the comment.</p>
    /// This field is required.
    pub fn comment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the comment.</p>
    pub fn set_comment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comment_id = input;
        self
    }
    /// <p>The ID of the comment.</p>
    pub fn get_comment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.comment_id
    }
    /// <p>The ID of the parent comment.</p>
    pub fn parent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent comment.</p>
    pub fn set_parent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_id = input;
        self
    }
    /// <p>The ID of the parent comment.</p>
    pub fn get_parent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_id
    }
    /// <p>The ID of the root comment in the thread.</p>
    pub fn thread_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thread_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the root comment in the thread.</p>
    pub fn set_thread_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thread_id = input;
        self
    }
    /// <p>The ID of the root comment in the thread.</p>
    pub fn get_thread_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.thread_id
    }
    /// <p>The text of the comment.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text of the comment.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The text of the comment.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>The details of the user who made the comment.</p>
    pub fn contributor(mut self, input: crate::types::User) -> Self {
        self.contributor = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of the user who made the comment.</p>
    pub fn set_contributor(mut self, input: ::std::option::Option<crate::types::User>) -> Self {
        self.contributor = input;
        self
    }
    /// <p>The details of the user who made the comment.</p>
    pub fn get_contributor(&self) -> &::std::option::Option<crate::types::User> {
        &self.contributor
    }
    /// <p>The time that the comment was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the comment was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The time that the comment was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The status of the comment.</p>
    pub fn status(mut self, input: crate::types::CommentStatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the comment.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CommentStatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the comment.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CommentStatusType> {
        &self.status
    }
    /// <p>The visibility of the comment. Options are either PRIVATE, where the comment is visible only to the comment author and document owner and co-owners, or PUBLIC, where the comment is visible to document owners, co-owners, and contributors.</p>
    pub fn visibility(mut self, input: crate::types::CommentVisibilityType) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility of the comment. Options are either PRIVATE, where the comment is visible only to the comment author and document owner and co-owners, or PUBLIC, where the comment is visible to document owners, co-owners, and contributors.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::CommentVisibilityType>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The visibility of the comment. Options are either PRIVATE, where the comment is visible only to the comment author and document owner and co-owners, or PUBLIC, where the comment is visible to document owners, co-owners, and contributors.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::CommentVisibilityType> {
        &self.visibility
    }
    /// <p>If the comment is a reply to another user's comment, this field contains the user ID of the user being replied to.</p>
    pub fn recipient_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipient_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the comment is a reply to another user's comment, this field contains the user ID of the user being replied to.</p>
    pub fn set_recipient_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipient_id = input;
        self
    }
    /// <p>If the comment is a reply to another user's comment, this field contains the user ID of the user being replied to.</p>
    pub fn get_recipient_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipient_id
    }
    /// Consumes the builder and constructs a [`Comment`](crate::types::Comment).
    /// This method will fail if any of the following fields are not set:
    /// - [`comment_id`](crate::types::builders::CommentBuilder::comment_id)
    pub fn build(self) -> ::std::result::Result<crate::types::Comment, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Comment {
            comment_id: self.comment_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comment_id",
                    "comment_id was not specified but it is required when building Comment",
                )
            })?,
            parent_id: self.parent_id,
            thread_id: self.thread_id,
            text: self.text,
            contributor: self.contributor,
            created_timestamp: self.created_timestamp,
            status: self.status,
            visibility: self.visibility,
            recipient_id: self.recipient_id,
        })
    }
}
impl ::std::fmt::Debug for CommentBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CommentBuilder");
        formatter.field("comment_id", &self.comment_id);
        formatter.field("parent_id", &self.parent_id);
        formatter.field("thread_id", &self.thread_id);
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("contributor", &self.contributor);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("status", &self.status);
        formatter.field("visibility", &self.visibility);
        formatter.field("recipient_id", &self.recipient_id);
        formatter.finish()
    }
}
