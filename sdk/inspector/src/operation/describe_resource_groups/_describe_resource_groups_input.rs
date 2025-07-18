// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeResourceGroupsInput {
    /// <p>The ARN that specifies the resource group that you want to describe.</p>
    pub resource_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeResourceGroupsInput {
    /// <p>The ARN that specifies the resource group that you want to describe.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_group_arns.is_none()`.
    pub fn resource_group_arns(&self) -> &[::std::string::String] {
        self.resource_group_arns.as_deref().unwrap_or_default()
    }
}
impl DescribeResourceGroupsInput {
    /// Creates a new builder-style object to manufacture [`DescribeResourceGroupsInput`](crate::operation::describe_resource_groups::DescribeResourceGroupsInput).
    pub fn builder() -> crate::operation::describe_resource_groups::builders::DescribeResourceGroupsInputBuilder {
        crate::operation::describe_resource_groups::builders::DescribeResourceGroupsInputBuilder::default()
    }
}

/// A builder for [`DescribeResourceGroupsInput`](crate::operation::describe_resource_groups::DescribeResourceGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeResourceGroupsInputBuilder {
    pub(crate) resource_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeResourceGroupsInputBuilder {
    /// Appends an item to `resource_group_arns`.
    ///
    /// To override the contents of this collection use [`set_resource_group_arns`](Self::set_resource_group_arns).
    ///
    /// <p>The ARN that specifies the resource group that you want to describe.</p>
    pub fn resource_group_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_group_arns.unwrap_or_default();
        v.push(input.into());
        self.resource_group_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARN that specifies the resource group that you want to describe.</p>
    pub fn set_resource_group_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_group_arns = input;
        self
    }
    /// <p>The ARN that specifies the resource group that you want to describe.</p>
    pub fn get_resource_group_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_group_arns
    }
    /// Consumes the builder and constructs a [`DescribeResourceGroupsInput`](crate::operation::describe_resource_groups::DescribeResourceGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_resource_groups::DescribeResourceGroupsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_resource_groups::DescribeResourceGroupsInput {
            resource_group_arns: self.resource_group_arns,
        })
    }
}
