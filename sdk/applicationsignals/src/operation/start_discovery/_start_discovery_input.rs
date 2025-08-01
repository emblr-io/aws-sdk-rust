// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDiscoveryInput {}
impl StartDiscoveryInput {
    /// Creates a new builder-style object to manufacture [`StartDiscoveryInput`](crate::operation::start_discovery::StartDiscoveryInput).
    pub fn builder() -> crate::operation::start_discovery::builders::StartDiscoveryInputBuilder {
        crate::operation::start_discovery::builders::StartDiscoveryInputBuilder::default()
    }
}

/// A builder for [`StartDiscoveryInput`](crate::operation::start_discovery::StartDiscoveryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDiscoveryInputBuilder {}
impl StartDiscoveryInputBuilder {
    /// Consumes the builder and constructs a [`StartDiscoveryInput`](crate::operation::start_discovery::StartDiscoveryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_discovery::StartDiscoveryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_discovery::StartDiscoveryInput {})
    }
}
