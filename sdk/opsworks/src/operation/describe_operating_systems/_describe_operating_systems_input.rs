// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOperatingSystemsInput {}
impl DescribeOperatingSystemsInput {
    /// Creates a new builder-style object to manufacture [`DescribeOperatingSystemsInput`](crate::operation::describe_operating_systems::DescribeOperatingSystemsInput).
    pub fn builder() -> crate::operation::describe_operating_systems::builders::DescribeOperatingSystemsInputBuilder {
        crate::operation::describe_operating_systems::builders::DescribeOperatingSystemsInputBuilder::default()
    }
}

/// A builder for [`DescribeOperatingSystemsInput`](crate::operation::describe_operating_systems::DescribeOperatingSystemsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOperatingSystemsInputBuilder {}
impl DescribeOperatingSystemsInputBuilder {
    /// Consumes the builder and constructs a [`DescribeOperatingSystemsInput`](crate::operation::describe_operating_systems::DescribeOperatingSystemsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_operating_systems::DescribeOperatingSystemsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_operating_systems::DescribeOperatingSystemsInput {})
    }
}
