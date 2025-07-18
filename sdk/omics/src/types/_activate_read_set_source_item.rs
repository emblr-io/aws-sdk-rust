// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A source for a read set activation job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivateReadSetSourceItem {
    /// <p>The source's read set ID.</p>
    pub read_set_id: ::std::string::String,
    /// <p>The source's status.</p>
    pub status: crate::types::ReadSetActivationJobItemStatus,
    /// <p>The source's status message.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl ActivateReadSetSourceItem {
    /// <p>The source's read set ID.</p>
    pub fn read_set_id(&self) -> &str {
        use std::ops::Deref;
        self.read_set_id.deref()
    }
    /// <p>The source's status.</p>
    pub fn status(&self) -> &crate::types::ReadSetActivationJobItemStatus {
        &self.status
    }
    /// <p>The source's status message.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl ActivateReadSetSourceItem {
    /// Creates a new builder-style object to manufacture [`ActivateReadSetSourceItem`](crate::types::ActivateReadSetSourceItem).
    pub fn builder() -> crate::types::builders::ActivateReadSetSourceItemBuilder {
        crate::types::builders::ActivateReadSetSourceItemBuilder::default()
    }
}

/// A builder for [`ActivateReadSetSourceItem`](crate::types::ActivateReadSetSourceItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivateReadSetSourceItemBuilder {
    pub(crate) read_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ReadSetActivationJobItemStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl ActivateReadSetSourceItemBuilder {
    /// <p>The source's read set ID.</p>
    /// This field is required.
    pub fn read_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.read_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source's read set ID.</p>
    pub fn set_read_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.read_set_id = input;
        self
    }
    /// <p>The source's read set ID.</p>
    pub fn get_read_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.read_set_id
    }
    /// <p>The source's status.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ReadSetActivationJobItemStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source's status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ReadSetActivationJobItemStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The source's status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ReadSetActivationJobItemStatus> {
        &self.status
    }
    /// <p>The source's status message.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source's status message.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The source's status message.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`ActivateReadSetSourceItem`](crate::types::ActivateReadSetSourceItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`read_set_id`](crate::types::builders::ActivateReadSetSourceItemBuilder::read_set_id)
    /// - [`status`](crate::types::builders::ActivateReadSetSourceItemBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::ActivateReadSetSourceItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ActivateReadSetSourceItem {
            read_set_id: self.read_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "read_set_id",
                    "read_set_id was not specified but it is required when building ActivateReadSetSourceItem",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building ActivateReadSetSourceItem",
                )
            })?,
            status_message: self.status_message,
        })
    }
}
