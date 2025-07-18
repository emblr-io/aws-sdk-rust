// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteClusterSecurityGroupInput {
    /// <p>The name of the cluster security group to be deleted.</p>
    pub cluster_security_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterSecurityGroupInput {
    /// <p>The name of the cluster security group to be deleted.</p>
    pub fn cluster_security_group_name(&self) -> ::std::option::Option<&str> {
        self.cluster_security_group_name.as_deref()
    }
}
impl DeleteClusterSecurityGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteClusterSecurityGroupInput`](crate::operation::delete_cluster_security_group::DeleteClusterSecurityGroupInput).
    pub fn builder() -> crate::operation::delete_cluster_security_group::builders::DeleteClusterSecurityGroupInputBuilder {
        crate::operation::delete_cluster_security_group::builders::DeleteClusterSecurityGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteClusterSecurityGroupInput`](crate::operation::delete_cluster_security_group::DeleteClusterSecurityGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteClusterSecurityGroupInputBuilder {
    pub(crate) cluster_security_group_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterSecurityGroupInputBuilder {
    /// <p>The name of the cluster security group to be deleted.</p>
    /// This field is required.
    pub fn cluster_security_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_security_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster security group to be deleted.</p>
    pub fn set_cluster_security_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_security_group_name = input;
        self
    }
    /// <p>The name of the cluster security group to be deleted.</p>
    pub fn get_cluster_security_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_security_group_name
    }
    /// Consumes the builder and constructs a [`DeleteClusterSecurityGroupInput`](crate::operation::delete_cluster_security_group::DeleteClusterSecurityGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_cluster_security_group::DeleteClusterSecurityGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_cluster_security_group::DeleteClusterSecurityGroupInput {
            cluster_security_group_name: self.cluster_security_group_name,
        })
    }
}
