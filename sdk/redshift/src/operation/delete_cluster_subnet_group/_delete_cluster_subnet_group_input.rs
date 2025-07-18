// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteClusterSubnetGroupInput {
    /// <p>The name of the cluster subnet group name to be deleted.</p>
    pub cluster_subnet_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterSubnetGroupInput {
    /// <p>The name of the cluster subnet group name to be deleted.</p>
    pub fn cluster_subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.cluster_subnet_group_name.as_deref()
    }
}
impl DeleteClusterSubnetGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteClusterSubnetGroupInput`](crate::operation::delete_cluster_subnet_group::DeleteClusterSubnetGroupInput).
    pub fn builder() -> crate::operation::delete_cluster_subnet_group::builders::DeleteClusterSubnetGroupInputBuilder {
        crate::operation::delete_cluster_subnet_group::builders::DeleteClusterSubnetGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteClusterSubnetGroupInput`](crate::operation::delete_cluster_subnet_group::DeleteClusterSubnetGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteClusterSubnetGroupInputBuilder {
    pub(crate) cluster_subnet_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterSubnetGroupInputBuilder {
    /// <p>The name of the cluster subnet group name to be deleted.</p>
    /// This field is required.
    pub fn cluster_subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster subnet group name to be deleted.</p>
    pub fn set_cluster_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_subnet_group_name = input;
        self
    }
    /// <p>The name of the cluster subnet group name to be deleted.</p>
    pub fn get_cluster_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_subnet_group_name
    }
    /// Consumes the builder and constructs a [`DeleteClusterSubnetGroupInput`](crate::operation::delete_cluster_subnet_group::DeleteClusterSubnetGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_cluster_subnet_group::DeleteClusterSubnetGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_cluster_subnet_group::DeleteClusterSubnetGroupInput {
            cluster_subnet_group_name: self.cluster_subnet_group_name,
        })
    }
}
