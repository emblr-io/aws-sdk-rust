// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCommentContentOutput {
    /// <p>Information about the comment you just deleted.</p>
    pub comment: ::std::option::Option<crate::types::Comment>,
    _request_id: Option<String>,
}
impl DeleteCommentContentOutput {
    /// <p>Information about the comment you just deleted.</p>
    pub fn comment(&self) -> ::std::option::Option<&crate::types::Comment> {
        self.comment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteCommentContentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteCommentContentOutput {
    /// Creates a new builder-style object to manufacture [`DeleteCommentContentOutput`](crate::operation::delete_comment_content::DeleteCommentContentOutput).
    pub fn builder() -> crate::operation::delete_comment_content::builders::DeleteCommentContentOutputBuilder {
        crate::operation::delete_comment_content::builders::DeleteCommentContentOutputBuilder::default()
    }
}

/// A builder for [`DeleteCommentContentOutput`](crate::operation::delete_comment_content::DeleteCommentContentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCommentContentOutputBuilder {
    pub(crate) comment: ::std::option::Option<crate::types::Comment>,
    _request_id: Option<String>,
}
impl DeleteCommentContentOutputBuilder {
    /// <p>Information about the comment you just deleted.</p>
    pub fn comment(mut self, input: crate::types::Comment) -> Self {
        self.comment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the comment you just deleted.</p>
    pub fn set_comment(mut self, input: ::std::option::Option<crate::types::Comment>) -> Self {
        self.comment = input;
        self
    }
    /// <p>Information about the comment you just deleted.</p>
    pub fn get_comment(&self) -> &::std::option::Option<crate::types::Comment> {
        &self.comment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteCommentContentOutput`](crate::operation::delete_comment_content::DeleteCommentContentOutput).
    pub fn build(self) -> crate::operation::delete_comment_content::DeleteCommentContentOutput {
        crate::operation::delete_comment_content::DeleteCommentContentOutput {
            comment: self.comment,
            _request_id: self._request_id,
        }
    }
}
