// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeVirtualClusterInput {
    /// <p>The ID of the virtual cluster that will be described.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl DescribeVirtualClusterInput {
    /// <p>The ID of the virtual cluster that will be described.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DescribeVirtualClusterInput {
    /// Creates a new builder-style object to manufacture [`DescribeVirtualClusterInput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterInput).
    pub fn builder() -> crate::operation::describe_virtual_cluster::builders::DescribeVirtualClusterInputBuilder {
        crate::operation::describe_virtual_cluster::builders::DescribeVirtualClusterInputBuilder::default()
    }
}

/// A builder for [`DescribeVirtualClusterInput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeVirtualClusterInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DescribeVirtualClusterInputBuilder {
    /// <p>The ID of the virtual cluster that will be described.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual cluster that will be described.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the virtual cluster that will be described.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DescribeVirtualClusterInput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_virtual_cluster::DescribeVirtualClusterInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_virtual_cluster::DescribeVirtualClusterInput { id: self.id })
    }
}
