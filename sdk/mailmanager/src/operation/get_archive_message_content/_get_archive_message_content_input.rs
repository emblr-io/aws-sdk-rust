// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request to get the textual content of a specific email message stored in an archive.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetArchiveMessageContentInput {
    /// <p>The unique identifier of the archived email message.</p>
    pub archived_message_id: ::std::option::Option<::std::string::String>,
}
impl GetArchiveMessageContentInput {
    /// <p>The unique identifier of the archived email message.</p>
    pub fn archived_message_id(&self) -> ::std::option::Option<&str> {
        self.archived_message_id.as_deref()
    }
}
impl GetArchiveMessageContentInput {
    /// Creates a new builder-style object to manufacture [`GetArchiveMessageContentInput`](crate::operation::get_archive_message_content::GetArchiveMessageContentInput).
    pub fn builder() -> crate::operation::get_archive_message_content::builders::GetArchiveMessageContentInputBuilder {
        crate::operation::get_archive_message_content::builders::GetArchiveMessageContentInputBuilder::default()
    }
}

/// A builder for [`GetArchiveMessageContentInput`](crate::operation::get_archive_message_content::GetArchiveMessageContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetArchiveMessageContentInputBuilder {
    pub(crate) archived_message_id: ::std::option::Option<::std::string::String>,
}
impl GetArchiveMessageContentInputBuilder {
    /// <p>The unique identifier of the archived email message.</p>
    /// This field is required.
    pub fn archived_message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.archived_message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the archived email message.</p>
    pub fn set_archived_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.archived_message_id = input;
        self
    }
    /// <p>The unique identifier of the archived email message.</p>
    pub fn get_archived_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.archived_message_id
    }
    /// Consumes the builder and constructs a [`GetArchiveMessageContentInput`](crate::operation::get_archive_message_content::GetArchiveMessageContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_archive_message_content::GetArchiveMessageContentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_archive_message_content::GetArchiveMessageContentInput {
            archived_message_id: self.archived_message_id,
        })
    }
}
