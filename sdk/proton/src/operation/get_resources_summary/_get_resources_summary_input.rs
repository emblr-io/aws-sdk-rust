// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcesSummaryInput {}
impl GetResourcesSummaryInput {
    /// Creates a new builder-style object to manufacture [`GetResourcesSummaryInput`](crate::operation::get_resources_summary::GetResourcesSummaryInput).
    pub fn builder() -> crate::operation::get_resources_summary::builders::GetResourcesSummaryInputBuilder {
        crate::operation::get_resources_summary::builders::GetResourcesSummaryInputBuilder::default()
    }
}

/// A builder for [`GetResourcesSummaryInput`](crate::operation::get_resources_summary::GetResourcesSummaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcesSummaryInputBuilder {}
impl GetResourcesSummaryInputBuilder {
    /// Consumes the builder and constructs a [`GetResourcesSummaryInput`](crate::operation::get_resources_summary::GetResourcesSummaryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resources_summary::GetResourcesSummaryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_resources_summary::GetResourcesSummaryInput {})
    }
}
