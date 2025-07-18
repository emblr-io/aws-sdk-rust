// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAddonInput {
    /// <p>The name of your cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub addon_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAddonInput {
    /// <p>The name of your cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn addon_name(&self) -> ::std::option::Option<&str> {
        self.addon_name.as_deref()
    }
}
impl DescribeAddonInput {
    /// Creates a new builder-style object to manufacture [`DescribeAddonInput`](crate::operation::describe_addon::DescribeAddonInput).
    pub fn builder() -> crate::operation::describe_addon::builders::DescribeAddonInputBuilder {
        crate::operation::describe_addon::builders::DescribeAddonInputBuilder::default()
    }
}

/// A builder for [`DescribeAddonInput`](crate::operation::describe_addon::DescribeAddonInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAddonInputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) addon_name: ::std::option::Option<::std::string::String>,
}
impl DescribeAddonInputBuilder {
    /// <p>The name of your cluster.</p>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    /// This field is required.
    pub fn addon_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn set_addon_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_name = input;
        self
    }
    /// <p>The name of the add-on. The name must match one of the names returned by <a href="https://docs.aws.amazon.com/eks/latest/APIReference/API_ListAddons.html"> <code>ListAddons</code> </a>.</p>
    pub fn get_addon_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_name
    }
    /// Consumes the builder and constructs a [`DescribeAddonInput`](crate::operation::describe_addon::DescribeAddonInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_addon::DescribeAddonInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_addon::DescribeAddonInput {
            cluster_name: self.cluster_name,
            addon_name: self.addon_name,
        })
    }
}
