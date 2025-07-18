// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Empty request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCheckerIpRangesInput {}
impl GetCheckerIpRangesInput {
    /// Creates a new builder-style object to manufacture [`GetCheckerIpRangesInput`](crate::operation::get_checker_ip_ranges::GetCheckerIpRangesInput).
    pub fn builder() -> crate::operation::get_checker_ip_ranges::builders::GetCheckerIpRangesInputBuilder {
        crate::operation::get_checker_ip_ranges::builders::GetCheckerIpRangesInputBuilder::default()
    }
}

/// A builder for [`GetCheckerIpRangesInput`](crate::operation::get_checker_ip_ranges::GetCheckerIpRangesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCheckerIpRangesInputBuilder {}
impl GetCheckerIpRangesInputBuilder {
    /// Consumes the builder and constructs a [`GetCheckerIpRangesInput`](crate::operation::get_checker_ip_ranges::GetCheckerIpRangesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_checker_ip_ranges::GetCheckerIpRangesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_checker_ip_ranges::GetCheckerIpRangesInput {})
    }
}
