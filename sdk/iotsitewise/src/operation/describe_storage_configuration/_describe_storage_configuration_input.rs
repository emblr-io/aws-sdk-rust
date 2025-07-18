// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStorageConfigurationInput {}
impl DescribeStorageConfigurationInput {
    /// Creates a new builder-style object to manufacture [`DescribeStorageConfigurationInput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationInput).
    pub fn builder() -> crate::operation::describe_storage_configuration::builders::DescribeStorageConfigurationInputBuilder {
        crate::operation::describe_storage_configuration::builders::DescribeStorageConfigurationInputBuilder::default()
    }
}

/// A builder for [`DescribeStorageConfigurationInput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStorageConfigurationInputBuilder {}
impl DescribeStorageConfigurationInputBuilder {
    /// Consumes the builder and constructs a [`DescribeStorageConfigurationInput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_storage_configuration::DescribeStorageConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_storage_configuration::DescribeStorageConfigurationInput {})
    }
}
