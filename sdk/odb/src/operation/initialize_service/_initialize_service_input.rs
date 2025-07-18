// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InitializeServiceInput {}
impl InitializeServiceInput {
    /// Creates a new builder-style object to manufacture [`InitializeServiceInput`](crate::operation::initialize_service::InitializeServiceInput).
    pub fn builder() -> crate::operation::initialize_service::builders::InitializeServiceInputBuilder {
        crate::operation::initialize_service::builders::InitializeServiceInputBuilder::default()
    }
}

/// A builder for [`InitializeServiceInput`](crate::operation::initialize_service::InitializeServiceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InitializeServiceInputBuilder {}
impl InitializeServiceInputBuilder {
    /// Consumes the builder and constructs a [`InitializeServiceInput`](crate::operation::initialize_service::InitializeServiceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::initialize_service::InitializeServiceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::initialize_service::InitializeServiceInput {})
    }
}
