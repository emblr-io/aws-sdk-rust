// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The identifier of a node in a cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterNode {
    /// <p>Whether the node is a leader node or a compute node.</p>
    pub node_role: ::std::option::Option<::std::string::String>,
    /// <p>The private IP address of a node within a cluster.</p>
    pub private_ip_address: ::std::option::Option<::std::string::String>,
    /// <p>The public IP address of a node within a cluster.</p>
    pub public_ip_address: ::std::option::Option<::std::string::String>,
}
impl ClusterNode {
    /// <p>Whether the node is a leader node or a compute node.</p>
    pub fn node_role(&self) -> ::std::option::Option<&str> {
        self.node_role.as_deref()
    }
    /// <p>The private IP address of a node within a cluster.</p>
    pub fn private_ip_address(&self) -> ::std::option::Option<&str> {
        self.private_ip_address.as_deref()
    }
    /// <p>The public IP address of a node within a cluster.</p>
    pub fn public_ip_address(&self) -> ::std::option::Option<&str> {
        self.public_ip_address.as_deref()
    }
}
impl ClusterNode {
    /// Creates a new builder-style object to manufacture [`ClusterNode`](crate::types::ClusterNode).
    pub fn builder() -> crate::types::builders::ClusterNodeBuilder {
        crate::types::builders::ClusterNodeBuilder::default()
    }
}

/// A builder for [`ClusterNode`](crate::types::ClusterNode).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterNodeBuilder {
    pub(crate) node_role: ::std::option::Option<::std::string::String>,
    pub(crate) private_ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) public_ip_address: ::std::option::Option<::std::string::String>,
}
impl ClusterNodeBuilder {
    /// <p>Whether the node is a leader node or a compute node.</p>
    pub fn node_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Whether the node is a leader node or a compute node.</p>
    pub fn set_node_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_role = input;
        self
    }
    /// <p>Whether the node is a leader node or a compute node.</p>
    pub fn get_node_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_role
    }
    /// <p>The private IP address of a node within a cluster.</p>
    pub fn private_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.private_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The private IP address of a node within a cluster.</p>
    pub fn set_private_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.private_ip_address = input;
        self
    }
    /// <p>The private IP address of a node within a cluster.</p>
    pub fn get_private_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.private_ip_address
    }
    /// <p>The public IP address of a node within a cluster.</p>
    pub fn public_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The public IP address of a node within a cluster.</p>
    pub fn set_public_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_ip_address = input;
        self
    }
    /// <p>The public IP address of a node within a cluster.</p>
    pub fn get_public_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_ip_address
    }
    /// Consumes the builder and constructs a [`ClusterNode`](crate::types::ClusterNode).
    pub fn build(self) -> crate::types::ClusterNode {
        crate::types::ClusterNode {
            node_role: self.node_role,
            private_ip_address: self.private_ip_address,
            public_ip_address: self.public_ip_address,
        }
    }
}
