// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDiscoverySummaryInput {}
impl GetDiscoverySummaryInput {
    /// Creates a new builder-style object to manufacture [`GetDiscoverySummaryInput`](crate::operation::get_discovery_summary::GetDiscoverySummaryInput).
    pub fn builder() -> crate::operation::get_discovery_summary::builders::GetDiscoverySummaryInputBuilder {
        crate::operation::get_discovery_summary::builders::GetDiscoverySummaryInputBuilder::default()
    }
}

/// A builder for [`GetDiscoverySummaryInput`](crate::operation::get_discovery_summary::GetDiscoverySummaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDiscoverySummaryInputBuilder {}
impl GetDiscoverySummaryInputBuilder {
    /// Consumes the builder and constructs a [`GetDiscoverySummaryInput`](crate::operation::get_discovery_summary::GetDiscoverySummaryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_discovery_summary::GetDiscoverySummaryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_discovery_summary::GetDiscoverySummaryInput {})
    }
}
