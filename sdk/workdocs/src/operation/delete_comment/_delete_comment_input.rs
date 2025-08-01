// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DeleteCommentInput {
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub authentication_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the document.</p>
    pub document_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the document version.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the comment.</p>
    pub comment_id: ::std::option::Option<::std::string::String>,
}
impl DeleteCommentInput {
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn authentication_token(&self) -> ::std::option::Option<&str> {
        self.authentication_token.as_deref()
    }
    /// <p>The ID of the document.</p>
    pub fn document_id(&self) -> ::std::option::Option<&str> {
        self.document_id.as_deref()
    }
    /// <p>The ID of the document version.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>The ID of the comment.</p>
    pub fn comment_id(&self) -> ::std::option::Option<&str> {
        self.comment_id.as_deref()
    }
}
impl ::std::fmt::Debug for DeleteCommentInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteCommentInput");
        formatter.field("authentication_token", &"*** Sensitive Data Redacted ***");
        formatter.field("document_id", &self.document_id);
        formatter.field("version_id", &self.version_id);
        formatter.field("comment_id", &self.comment_id);
        formatter.finish()
    }
}
impl DeleteCommentInput {
    /// Creates a new builder-style object to manufacture [`DeleteCommentInput`](crate::operation::delete_comment::DeleteCommentInput).
    pub fn builder() -> crate::operation::delete_comment::builders::DeleteCommentInputBuilder {
        crate::operation::delete_comment::builders::DeleteCommentInputBuilder::default()
    }
}

/// A builder for [`DeleteCommentInput`](crate::operation::delete_comment::DeleteCommentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeleteCommentInputBuilder {
    pub(crate) authentication_token: ::std::option::Option<::std::string::String>,
    pub(crate) document_id: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) comment_id: ::std::option::Option<::std::string::String>,
}
impl DeleteCommentInputBuilder {
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn authentication_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authentication_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn set_authentication_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authentication_token = input;
        self
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn get_authentication_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.authentication_token
    }
    /// <p>The ID of the document.</p>
    /// This field is required.
    pub fn document_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the document.</p>
    pub fn set_document_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_id = input;
        self
    }
    /// <p>The ID of the document.</p>
    pub fn get_document_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_id
    }
    /// <p>The ID of the document version.</p>
    /// This field is required.
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the document version.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The ID of the document version.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
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
    /// Consumes the builder and constructs a [`DeleteCommentInput`](crate::operation::delete_comment::DeleteCommentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_comment::DeleteCommentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_comment::DeleteCommentInput {
            authentication_token: self.authentication_token,
            document_id: self.document_id,
            version_id: self.version_id,
            comment_id: self.comment_id,
        })
    }
}
impl ::std::fmt::Debug for DeleteCommentInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteCommentInputBuilder");
        formatter.field("authentication_token", &"*** Sensitive Data Redacted ***");
        formatter.field("document_id", &self.document_id);
        formatter.field("version_id", &self.version_id);
        formatter.field("comment_id", &self.comment_id);
        formatter.finish()
    }
}
