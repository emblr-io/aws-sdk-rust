// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAttachmentInput {
    /// <p>The ID of the attachment to return. Attachment IDs are returned by the <code>DescribeCommunications</code> operation.</p>
    pub attachment_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAttachmentInput {
    /// <p>The ID of the attachment to return. Attachment IDs are returned by the <code>DescribeCommunications</code> operation.</p>
    pub fn attachment_id(&self) -> ::std::option::Option<&str> {
        self.attachment_id.as_deref()
    }
}
impl DescribeAttachmentInput {
    /// Creates a new builder-style object to manufacture [`DescribeAttachmentInput`](crate::operation::describe_attachment::DescribeAttachmentInput).
    pub fn builder() -> crate::operation::describe_attachment::builders::DescribeAttachmentInputBuilder {
        crate::operation::describe_attachment::builders::DescribeAttachmentInputBuilder::default()
    }
}

/// A builder for [`DescribeAttachmentInput`](crate::operation::describe_attachment::DescribeAttachmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAttachmentInputBuilder {
    pub(crate) attachment_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAttachmentInputBuilder {
    /// <p>The ID of the attachment to return. Attachment IDs are returned by the <code>DescribeCommunications</code> operation.</p>
    /// This field is required.
    pub fn attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the attachment to return. Attachment IDs are returned by the <code>DescribeCommunications</code> operation.</p>
    pub fn set_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attachment_id = input;
        self
    }
    /// <p>The ID of the attachment to return. Attachment IDs are returned by the <code>DescribeCommunications</code> operation.</p>
    pub fn get_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.attachment_id
    }
    /// Consumes the builder and constructs a [`DescribeAttachmentInput`](crate::operation::describe_attachment::DescribeAttachmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_attachment::DescribeAttachmentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_attachment::DescribeAttachmentInput {
            attachment_id: self.attachment_id,
        })
    }
}
