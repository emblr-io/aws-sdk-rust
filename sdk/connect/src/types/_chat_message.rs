// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A chat message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChatMessage {
    /// <p>The type of the content. Supported types are <code>text/plain</code>, <code>text/markdown</code>, <code>application/json</code>, and <code>application/vnd.amazonaws.connect.message.interactive.response</code>.</p>
    pub content_type: ::std::string::String,
    /// <p>The content of the chat message.</p>
    /// <ul>
    /// <li>
    /// <p>For <code>text/plain</code> and <code>text/markdown</code>, the Length Constraints are Minimum of 1, Maximum of 1024.</p></li>
    /// <li>
    /// <p>For <code>application/json</code>, the Length Constraints are Minimum of 1, Maximum of 12000.</p></li>
    /// <li>
    /// <p>For <code>application/vnd.amazonaws.connect.message.interactive.response</code>, the Length Constraints are Minimum of 1, Maximum of 12288.</p></li>
    /// </ul>
    pub content: ::std::string::String,
}
impl ChatMessage {
    /// <p>The type of the content. Supported types are <code>text/plain</code>, <code>text/markdown</code>, <code>application/json</code>, and <code>application/vnd.amazonaws.connect.message.interactive.response</code>.</p>
    pub fn content_type(&self) -> &str {
        use std::ops::Deref;
        self.content_type.deref()
    }
    /// <p>The content of the chat message.</p>
    /// <ul>
    /// <li>
    /// <p>For <code>text/plain</code> and <code>text/markdown</code>, the Length Constraints are Minimum of 1, Maximum of 1024.</p></li>
    /// <li>
    /// <p>For <code>application/json</code>, the Length Constraints are Minimum of 1, Maximum of 12000.</p></li>
    /// <li>
    /// <p>For <code>application/vnd.amazonaws.connect.message.interactive.response</code>, the Length Constraints are Minimum of 1, Maximum of 12288.</p></li>
    /// </ul>
    pub fn content(&self) -> &str {
        use std::ops::Deref;
        self.content.deref()
    }
}
impl ChatMessage {
    /// Creates a new builder-style object to manufacture [`ChatMessage`](crate::types::ChatMessage).
    pub fn builder() -> crate::types::builders::ChatMessageBuilder {
        crate::types::builders::ChatMessageBuilder::default()
    }
}

/// A builder for [`ChatMessage`](crate::types::ChatMessage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChatMessageBuilder {
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
}
impl ChatMessageBuilder {
    /// <p>The type of the content. Supported types are <code>text/plain</code>, <code>text/markdown</code>, <code>application/json</code>, and <code>application/vnd.amazonaws.connect.message.interactive.response</code>.</p>
    /// This field is required.
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the content. Supported types are <code>text/plain</code>, <code>text/markdown</code>, <code>application/json</code>, and <code>application/vnd.amazonaws.connect.message.interactive.response</code>.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The type of the content. Supported types are <code>text/plain</code>, <code>text/markdown</code>, <code>application/json</code>, and <code>application/vnd.amazonaws.connect.message.interactive.response</code>.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>The content of the chat message.</p>
    /// <ul>
    /// <li>
    /// <p>For <code>text/plain</code> and <code>text/markdown</code>, the Length Constraints are Minimum of 1, Maximum of 1024.</p></li>
    /// <li>
    /// <p>For <code>application/json</code>, the Length Constraints are Minimum of 1, Maximum of 12000.</p></li>
    /// <li>
    /// <p>For <code>application/vnd.amazonaws.connect.message.interactive.response</code>, the Length Constraints are Minimum of 1, Maximum of 12288.</p></li>
    /// </ul>
    /// This field is required.
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the chat message.</p>
    /// <ul>
    /// <li>
    /// <p>For <code>text/plain</code> and <code>text/markdown</code>, the Length Constraints are Minimum of 1, Maximum of 1024.</p></li>
    /// <li>
    /// <p>For <code>application/json</code>, the Length Constraints are Minimum of 1, Maximum of 12000.</p></li>
    /// <li>
    /// <p>For <code>application/vnd.amazonaws.connect.message.interactive.response</code>, the Length Constraints are Minimum of 1, Maximum of 12288.</p></li>
    /// </ul>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the chat message.</p>
    /// <ul>
    /// <li>
    /// <p>For <code>text/plain</code> and <code>text/markdown</code>, the Length Constraints are Minimum of 1, Maximum of 1024.</p></li>
    /// <li>
    /// <p>For <code>application/json</code>, the Length Constraints are Minimum of 1, Maximum of 12000.</p></li>
    /// <li>
    /// <p>For <code>application/vnd.amazonaws.connect.message.interactive.response</code>, the Length Constraints are Minimum of 1, Maximum of 12288.</p></li>
    /// </ul>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Consumes the builder and constructs a [`ChatMessage`](crate::types::ChatMessage).
    /// This method will fail if any of the following fields are not set:
    /// - [`content_type`](crate::types::builders::ChatMessageBuilder::content_type)
    /// - [`content`](crate::types::builders::ChatMessageBuilder::content)
    pub fn build(self) -> ::std::result::Result<crate::types::ChatMessage, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChatMessage {
            content_type: self.content_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content_type",
                    "content_type was not specified but it is required when building ChatMessage",
                )
            })?,
            content: self.content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content",
                    "content was not specified but it is required when building ChatMessage",
                )
            })?,
        })
    }
}
