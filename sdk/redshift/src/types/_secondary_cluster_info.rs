// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The AvailabilityZone and ClusterNodes information of the secondary compute unit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecondaryClusterInfo {
    /// <p>The name of the Availability Zone in which the secondary compute unit of the cluster is located.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The nodes in the secondary compute unit.</p>
    pub cluster_nodes: ::std::option::Option<::std::vec::Vec<crate::types::ClusterNode>>,
}
impl SecondaryClusterInfo {
    /// <p>The name of the Availability Zone in which the secondary compute unit of the cluster is located.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The nodes in the secondary compute unit.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cluster_nodes.is_none()`.
    pub fn cluster_nodes(&self) -> &[crate::types::ClusterNode] {
        self.cluster_nodes.as_deref().unwrap_or_default()
    }
}
impl SecondaryClusterInfo {
    /// Creates a new builder-style object to manufacture [`SecondaryClusterInfo`](crate::types::SecondaryClusterInfo).
    pub fn builder() -> crate::types::builders::SecondaryClusterInfoBuilder {
        crate::types::builders::SecondaryClusterInfoBuilder::default()
    }
}

/// A builder for [`SecondaryClusterInfo`](crate::types::SecondaryClusterInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecondaryClusterInfoBuilder {
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_nodes: ::std::option::Option<::std::vec::Vec<crate::types::ClusterNode>>,
}
impl SecondaryClusterInfoBuilder {
    /// <p>The name of the Availability Zone in which the secondary compute unit of the cluster is located.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Availability Zone in which the secondary compute unit of the cluster is located.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The name of the Availability Zone in which the secondary compute unit of the cluster is located.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// Appends an item to `cluster_nodes`.
    ///
    /// To override the contents of this collection use [`set_cluster_nodes`](Self::set_cluster_nodes).
    ///
    /// <p>The nodes in the secondary compute unit.</p>
    pub fn cluster_nodes(mut self, input: crate::types::ClusterNode) -> Self {
        let mut v = self.cluster_nodes.unwrap_or_default();
        v.push(input);
        self.cluster_nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The nodes in the secondary compute unit.</p>
    pub fn set_cluster_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ClusterNode>>) -> Self {
        self.cluster_nodes = input;
        self
    }
    /// <p>The nodes in the secondary compute unit.</p>
    pub fn get_cluster_nodes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ClusterNode>> {
        &self.cluster_nodes
    }
    /// Consumes the builder and constructs a [`SecondaryClusterInfo`](crate::types::SecondaryClusterInfo).
    pub fn build(self) -> crate::types::SecondaryClusterInfo {
        crate::types::SecondaryClusterInfo {
            availability_zone: self.availability_zone,
            cluster_nodes: self.cluster_nodes,
        }
    }
}
