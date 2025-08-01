// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConnectAttachmentInput {
    /// <p>The ID of the attachment.</p>
    pub attachment_id: ::std::option::Option<::std::string::String>,
}
impl GetConnectAttachmentInput {
    /// <p>The ID of the attachment.</p>
    pub fn attachment_id(&self) -> ::std::option::Option<&str> {
        self.attachment_id.as_deref()
    }
}
impl GetConnectAttachmentInput {
    /// Creates a new builder-style object to manufacture [`GetConnectAttachmentInput`](crate::operation::get_connect_attachment::GetConnectAttachmentInput).
    pub fn builder() -> crate::operation::get_connect_attachment::builders::GetConnectAttachmentInputBuilder {
        crate::operation::get_connect_attachment::builders::GetConnectAttachmentInputBuilder::default()
    }
}

/// A builder for [`GetConnectAttachmentInput`](crate::operation::get_connect_attachment::GetConnectAttachmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConnectAttachmentInputBuilder {
    pub(crate) attachment_id: ::std::option::Option<::std::string::String>,
}
impl GetConnectAttachmentInputBuilder {
    /// <p>The ID of the attachment.</p>
    /// This field is required.
    pub fn attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the attachment.</p>
    pub fn set_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attachment_id = input;
        self
    }
    /// <p>The ID of the attachment.</p>
    pub fn get_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.attachment_id
    }
    /// Consumes the builder and constructs a [`GetConnectAttachmentInput`](crate::operation::get_connect_attachment::GetConnectAttachmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_connect_attachment::GetConnectAttachmentInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_connect_attachment::GetConnectAttachmentInput {
            attachment_id: self.attachment_id,
        })
    }
}
