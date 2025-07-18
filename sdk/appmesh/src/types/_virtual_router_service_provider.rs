// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a virtual node service provider.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualRouterServiceProvider {
    /// <p>The name of the virtual router that is acting as a service provider.</p>
    pub virtual_router_name: ::std::string::String,
}
impl VirtualRouterServiceProvider {
    /// <p>The name of the virtual router that is acting as a service provider.</p>
    pub fn virtual_router_name(&self) -> &str {
        use std::ops::Deref;
        self.virtual_router_name.deref()
    }
}
impl VirtualRouterServiceProvider {
    /// Creates a new builder-style object to manufacture [`VirtualRouterServiceProvider`](crate::types::VirtualRouterServiceProvider).
    pub fn builder() -> crate::types::builders::VirtualRouterServiceProviderBuilder {
        crate::types::builders::VirtualRouterServiceProviderBuilder::default()
    }
}

/// A builder for [`VirtualRouterServiceProvider`](crate::types::VirtualRouterServiceProvider).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualRouterServiceProviderBuilder {
    pub(crate) virtual_router_name: ::std::option::Option<::std::string::String>,
}
impl VirtualRouterServiceProviderBuilder {
    /// <p>The name of the virtual router that is acting as a service provider.</p>
    /// This field is required.
    pub fn virtual_router_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_router_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the virtual router that is acting as a service provider.</p>
    pub fn set_virtual_router_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_router_name = input;
        self
    }
    /// <p>The name of the virtual router that is acting as a service provider.</p>
    pub fn get_virtual_router_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_router_name
    }
    /// Consumes the builder and constructs a [`VirtualRouterServiceProvider`](crate::types::VirtualRouterServiceProvider).
    /// This method will fail if any of the following fields are not set:
    /// - [`virtual_router_name`](crate::types::builders::VirtualRouterServiceProviderBuilder::virtual_router_name)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualRouterServiceProvider, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualRouterServiceProvider {
            virtual_router_name: self.virtual_router_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "virtual_router_name",
                    "virtual_router_name was not specified but it is required when building VirtualRouterServiceProvider",
                )
            })?,
        })
    }
}
