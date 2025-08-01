// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterCustomEndpointInput {}
impl RegisterCustomEndpointInput {
    /// Creates a new builder-style object to manufacture [`RegisterCustomEndpointInput`](crate::operation::register_custom_endpoint::RegisterCustomEndpointInput).
    pub fn builder() -> crate::operation::register_custom_endpoint::builders::RegisterCustomEndpointInputBuilder {
        crate::operation::register_custom_endpoint::builders::RegisterCustomEndpointInputBuilder::default()
    }
}

/// A builder for [`RegisterCustomEndpointInput`](crate::operation::register_custom_endpoint::RegisterCustomEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterCustomEndpointInputBuilder {}
impl RegisterCustomEndpointInputBuilder {
    /// Consumes the builder and constructs a [`RegisterCustomEndpointInput`](crate::operation::register_custom_endpoint::RegisterCustomEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::register_custom_endpoint::RegisterCustomEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::register_custom_endpoint::RegisterCustomEndpointInput {})
    }
}
