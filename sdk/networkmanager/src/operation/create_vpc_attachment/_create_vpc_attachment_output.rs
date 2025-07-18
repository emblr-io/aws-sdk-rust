// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVpcAttachmentOutput {
    /// <p>Provides details about the VPC attachment.</p>
    pub vpc_attachment: ::std::option::Option<crate::types::VpcAttachment>,
    _request_id: Option<String>,
}
impl CreateVpcAttachmentOutput {
    /// <p>Provides details about the VPC attachment.</p>
    pub fn vpc_attachment(&self) -> ::std::option::Option<&crate::types::VpcAttachment> {
        self.vpc_attachment.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateVpcAttachmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateVpcAttachmentOutput {
    /// Creates a new builder-style object to manufacture [`CreateVpcAttachmentOutput`](crate::operation::create_vpc_attachment::CreateVpcAttachmentOutput).
    pub fn builder() -> crate::operation::create_vpc_attachment::builders::CreateVpcAttachmentOutputBuilder {
        crate::operation::create_vpc_attachment::builders::CreateVpcAttachmentOutputBuilder::default()
    }
}

/// A builder for [`CreateVpcAttachmentOutput`](crate::operation::create_vpc_attachment::CreateVpcAttachmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVpcAttachmentOutputBuilder {
    pub(crate) vpc_attachment: ::std::option::Option<crate::types::VpcAttachment>,
    _request_id: Option<String>,
}
impl CreateVpcAttachmentOutputBuilder {
    /// <p>Provides details about the VPC attachment.</p>
    pub fn vpc_attachment(mut self, input: crate::types::VpcAttachment) -> Self {
        self.vpc_attachment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides details about the VPC attachment.</p>
    pub fn set_vpc_attachment(mut self, input: ::std::option::Option<crate::types::VpcAttachment>) -> Self {
        self.vpc_attachment = input;
        self
    }
    /// <p>Provides details about the VPC attachment.</p>
    pub fn get_vpc_attachment(&self) -> &::std::option::Option<crate::types::VpcAttachment> {
        &self.vpc_attachment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateVpcAttachmentOutput`](crate::operation::create_vpc_attachment::CreateVpcAttachmentOutput).
    pub fn build(self) -> crate::operation::create_vpc_attachment::CreateVpcAttachmentOutput {
        crate::operation::create_vpc_attachment::CreateVpcAttachmentOutput {
            vpc_attachment: self.vpc_attachment,
            _request_id: self._request_id,
        }
    }
}
