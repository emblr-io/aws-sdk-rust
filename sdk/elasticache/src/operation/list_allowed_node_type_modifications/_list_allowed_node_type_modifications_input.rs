// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input parameters for the <code>ListAllowedNodeTypeModifications</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAllowedNodeTypeModificationsInput {
    /// <p>The name of the cluster you want to scale up to a larger node instanced type. ElastiCache uses the cluster id to identify the current node type of this cluster and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub cache_cluster_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the replication group want to scale up to a larger node type. ElastiCache uses the replication group id to identify the current node type being used by this replication group, and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub replication_group_id: ::std::option::Option<::std::string::String>,
}
impl ListAllowedNodeTypeModificationsInput {
    /// <p>The name of the cluster you want to scale up to a larger node instanced type. ElastiCache uses the cluster id to identify the current node type of this cluster and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn cache_cluster_id(&self) -> ::std::option::Option<&str> {
        self.cache_cluster_id.as_deref()
    }
    /// <p>The name of the replication group want to scale up to a larger node type. ElastiCache uses the replication group id to identify the current node type being used by this replication group, and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn replication_group_id(&self) -> ::std::option::Option<&str> {
        self.replication_group_id.as_deref()
    }
}
impl ListAllowedNodeTypeModificationsInput {
    /// Creates a new builder-style object to manufacture [`ListAllowedNodeTypeModificationsInput`](crate::operation::list_allowed_node_type_modifications::ListAllowedNodeTypeModificationsInput).
    pub fn builder() -> crate::operation::list_allowed_node_type_modifications::builders::ListAllowedNodeTypeModificationsInputBuilder {
        crate::operation::list_allowed_node_type_modifications::builders::ListAllowedNodeTypeModificationsInputBuilder::default()
    }
}

/// A builder for [`ListAllowedNodeTypeModificationsInput`](crate::operation::list_allowed_node_type_modifications::ListAllowedNodeTypeModificationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAllowedNodeTypeModificationsInputBuilder {
    pub(crate) cache_cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) replication_group_id: ::std::option::Option<::std::string::String>,
}
impl ListAllowedNodeTypeModificationsInputBuilder {
    /// <p>The name of the cluster you want to scale up to a larger node instanced type. ElastiCache uses the cluster id to identify the current node type of this cluster and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn cache_cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster you want to scale up to a larger node instanced type. ElastiCache uses the cluster id to identify the current node type of this cluster and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn set_cache_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_cluster_id = input;
        self
    }
    /// <p>The name of the cluster you want to scale up to a larger node instanced type. ElastiCache uses the cluster id to identify the current node type of this cluster and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn get_cache_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_cluster_id
    }
    /// <p>The name of the replication group want to scale up to a larger node type. ElastiCache uses the replication group id to identify the current node type being used by this replication group, and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn replication_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the replication group want to scale up to a larger node type. ElastiCache uses the replication group id to identify the current node type being used by this replication group, and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn set_replication_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_group_id = input;
        self
    }
    /// <p>The name of the replication group want to scale up to a larger node type. ElastiCache uses the replication group id to identify the current node type being used by this replication group, and from that to create a list of node types you can scale up to.</p><important>
    /// <p>You must provide a value for either the <code>CacheClusterId</code> or the <code>ReplicationGroupId</code>.</p>
    /// </important>
    pub fn get_replication_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_group_id
    }
    /// Consumes the builder and constructs a [`ListAllowedNodeTypeModificationsInput`](crate::operation::list_allowed_node_type_modifications::ListAllowedNodeTypeModificationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_allowed_node_type_modifications::ListAllowedNodeTypeModificationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_allowed_node_type_modifications::ListAllowedNodeTypeModificationsInput {
                cache_cluster_id: self.cache_cluster_id,
                replication_group_id: self.replication_group_id,
            },
        )
    }
}
