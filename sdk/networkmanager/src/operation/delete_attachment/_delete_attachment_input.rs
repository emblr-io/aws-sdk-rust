// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAttachmentInput {
    /// <p>The ID of the attachment to delete.</p>
    pub attachment_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAttachmentInput {
    /// <p>The ID of the attachment to delete.</p>
    pub fn attachment_id(&self) -> ::std::option::Option<&str> {
        self.attachment_id.as_deref()
    }
}
impl DeleteAttachmentInput {
    /// Creates a new builder-style object to manufacture [`DeleteAttachmentInput`](crate::operation::delete_attachment::DeleteAttachmentInput).
    pub fn builder() -> crate::operation::delete_attachment::builders::DeleteAttachmentInputBuilder {
        crate::operation::delete_attachment::builders::DeleteAttachmentInputBuilder::default()
    }
}

/// A builder for [`DeleteAttachmentInput`](crate::operation::delete_attachment::DeleteAttachmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAttachmentInputBuilder {
    pub(crate) attachment_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAttachmentInputBuilder {
    /// <p>The ID of the attachment to delete.</p>
    /// This field is required.
    pub fn attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the attachment to delete.</p>
    pub fn set_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attachment_id = input;
        self
    }
    /// <p>The ID of the attachment to delete.</p>
    pub fn get_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.attachment_id
    }
    /// Consumes the builder and constructs a [`DeleteAttachmentInput`](crate::operation::delete_attachment::DeleteAttachmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_attachment::DeleteAttachmentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_attachment::DeleteAttachmentInput {
            attachment_id: self.attachment_id,
        })
    }
}
