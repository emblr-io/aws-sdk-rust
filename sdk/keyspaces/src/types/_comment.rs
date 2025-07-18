// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An optional comment that describes the table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Comment {
    /// <p>An optional description of the table.</p>
    pub message: ::std::string::String,
}
impl Comment {
    /// <p>An optional description of the table.</p>
    pub fn message(&self) -> &str {
        use std::ops::Deref;
        self.message.deref()
    }
}
impl Comment {
    /// Creates a new builder-style object to manufacture [`Comment`](crate::types::Comment).
    pub fn builder() -> crate::types::builders::CommentBuilder {
        crate::types::builders::CommentBuilder::default()
    }
}

/// A builder for [`Comment`](crate::types::Comment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommentBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl CommentBuilder {
    /// <p>An optional description of the table.</p>
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description of the table.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>An optional description of the table.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`Comment`](crate::types::Comment).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::builders::CommentBuilder::message)
    pub fn build(self) -> ::std::result::Result<crate::types::Comment, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Comment {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building Comment",
                )
            })?,
        })
    }
}
