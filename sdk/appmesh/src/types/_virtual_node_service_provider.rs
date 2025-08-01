// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a virtual node service provider.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualNodeServiceProvider {
    /// <p>The name of the virtual node that is acting as a service provider.</p>
    pub virtual_node_name: ::std::string::String,
}
impl VirtualNodeServiceProvider {
    /// <p>The name of the virtual node that is acting as a service provider.</p>
    pub fn virtual_node_name(&self) -> &str {
        use std::ops::Deref;
        self.virtual_node_name.deref()
    }
}
impl VirtualNodeServiceProvider {
    /// Creates a new builder-style object to manufacture [`VirtualNodeServiceProvider`](crate::types::VirtualNodeServiceProvider).
    pub fn builder() -> crate::types::builders::VirtualNodeServiceProviderBuilder {
        crate::types::builders::VirtualNodeServiceProviderBuilder::default()
    }
}

/// A builder for [`VirtualNodeServiceProvider`](crate::types::VirtualNodeServiceProvider).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualNodeServiceProviderBuilder {
    pub(crate) virtual_node_name: ::std::option::Option<::std::string::String>,
}
impl VirtualNodeServiceProviderBuilder {
    /// <p>The name of the virtual node that is acting as a service provider.</p>
    /// This field is required.
    pub fn virtual_node_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_node_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the virtual node that is acting as a service provider.</p>
    pub fn set_virtual_node_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_node_name = input;
        self
    }
    /// <p>The name of the virtual node that is acting as a service provider.</p>
    pub fn get_virtual_node_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_node_name
    }
    /// Consumes the builder and constructs a [`VirtualNodeServiceProvider`](crate::types::VirtualNodeServiceProvider).
    /// This method will fail if any of the following fields are not set:
    /// - [`virtual_node_name`](crate::types::builders::VirtualNodeServiceProviderBuilder::virtual_node_name)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualNodeServiceProvider, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualNodeServiceProvider {
            virtual_node_name: self.virtual_node_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "virtual_node_name",
                    "virtual_node_name was not specified but it is required when building VirtualNodeServiceProvider",
                )
            })?,
        })
    }
}
