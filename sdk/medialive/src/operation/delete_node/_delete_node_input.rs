// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for DeleteNodeRequest
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteNodeInput {
    /// The ID of the cluster
    pub cluster_id: ::std::option::Option<::std::string::String>,
    /// The ID of the node.
    pub node_id: ::std::option::Option<::std::string::String>,
}
impl DeleteNodeInput {
    /// The ID of the cluster
    pub fn cluster_id(&self) -> ::std::option::Option<&str> {
        self.cluster_id.as_deref()
    }
    /// The ID of the node.
    pub fn node_id(&self) -> ::std::option::Option<&str> {
        self.node_id.as_deref()
    }
}
impl DeleteNodeInput {
    /// Creates a new builder-style object to manufacture [`DeleteNodeInput`](crate::operation::delete_node::DeleteNodeInput).
    pub fn builder() -> crate::operation::delete_node::builders::DeleteNodeInputBuilder {
        crate::operation::delete_node::builders::DeleteNodeInputBuilder::default()
    }
}

/// A builder for [`DeleteNodeInput`](crate::operation::delete_node::DeleteNodeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteNodeInputBuilder {
    pub(crate) cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) node_id: ::std::option::Option<::std::string::String>,
}
impl DeleteNodeInputBuilder {
    /// The ID of the cluster
    /// This field is required.
    pub fn cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the cluster
    pub fn set_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_id = input;
        self
    }
    /// The ID of the cluster
    pub fn get_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_id
    }
    /// The ID of the node.
    /// This field is required.
    pub fn node_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the node.
    pub fn set_node_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_id = input;
        self
    }
    /// The ID of the node.
    pub fn get_node_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_id
    }
    /// Consumes the builder and constructs a [`DeleteNodeInput`](crate::operation::delete_node::DeleteNodeInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_node::DeleteNodeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_node::DeleteNodeInput {
            cluster_id: self.cluster_id,
            node_id: self.node_id,
        })
    }
}
