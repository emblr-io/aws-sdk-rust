// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for attaching a VPC interface to an resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpcInterfaceAttachment {
    /// <p>The name of the VPC interface to use for this resource.</p>
    pub vpc_interface_name: ::std::option::Option<::std::string::String>,
}
impl VpcInterfaceAttachment {
    /// <p>The name of the VPC interface to use for this resource.</p>
    pub fn vpc_interface_name(&self) -> ::std::option::Option<&str> {
        self.vpc_interface_name.as_deref()
    }
}
impl VpcInterfaceAttachment {
    /// Creates a new builder-style object to manufacture [`VpcInterfaceAttachment`](crate::types::VpcInterfaceAttachment).
    pub fn builder() -> crate::types::builders::VpcInterfaceAttachmentBuilder {
        crate::types::builders::VpcInterfaceAttachmentBuilder::default()
    }
}

/// A builder for [`VpcInterfaceAttachment`](crate::types::VpcInterfaceAttachment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpcInterfaceAttachmentBuilder {
    pub(crate) vpc_interface_name: ::std::option::Option<::std::string::String>,
}
impl VpcInterfaceAttachmentBuilder {
    /// <p>The name of the VPC interface to use for this resource.</p>
    pub fn vpc_interface_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_interface_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the VPC interface to use for this resource.</p>
    pub fn set_vpc_interface_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_interface_name = input;
        self
    }
    /// <p>The name of the VPC interface to use for this resource.</p>
    pub fn get_vpc_interface_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_interface_name
    }
    /// Consumes the builder and constructs a [`VpcInterfaceAttachment`](crate::types::VpcInterfaceAttachment).
    pub fn build(self) -> crate::types::VpcInterfaceAttachment {
        crate::types::VpcInterfaceAttachment {
            vpc_interface_name: self.vpc_interface_name,
        }
    }
}
