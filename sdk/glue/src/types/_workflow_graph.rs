// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A workflow graph represents the complete workflow containing all the Glue components present in the workflow and all the directed connections between them.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkflowGraph {
    /// <p>A list of the the Glue components belong to the workflow represented as nodes.</p>
    pub nodes: ::std::option::Option<::std::vec::Vec<crate::types::Node>>,
    /// <p>A list of all the directed connections between the nodes belonging to the workflow.</p>
    pub edges: ::std::option::Option<::std::vec::Vec<crate::types::Edge>>,
}
impl WorkflowGraph {
    /// <p>A list of the the Glue components belong to the workflow represented as nodes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.nodes.is_none()`.
    pub fn nodes(&self) -> &[crate::types::Node] {
        self.nodes.as_deref().unwrap_or_default()
    }
    /// <p>A list of all the directed connections between the nodes belonging to the workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.edges.is_none()`.
    pub fn edges(&self) -> &[crate::types::Edge] {
        self.edges.as_deref().unwrap_or_default()
    }
}
impl WorkflowGraph {
    /// Creates a new builder-style object to manufacture [`WorkflowGraph`](crate::types::WorkflowGraph).
    pub fn builder() -> crate::types::builders::WorkflowGraphBuilder {
        crate::types::builders::WorkflowGraphBuilder::default()
    }
}

/// A builder for [`WorkflowGraph`](crate::types::WorkflowGraph).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkflowGraphBuilder {
    pub(crate) nodes: ::std::option::Option<::std::vec::Vec<crate::types::Node>>,
    pub(crate) edges: ::std::option::Option<::std::vec::Vec<crate::types::Edge>>,
}
impl WorkflowGraphBuilder {
    /// Appends an item to `nodes`.
    ///
    /// To override the contents of this collection use [`set_nodes`](Self::set_nodes).
    ///
    /// <p>A list of the the Glue components belong to the workflow represented as nodes.</p>
    pub fn nodes(mut self, input: crate::types::Node) -> Self {
        let mut v = self.nodes.unwrap_or_default();
        v.push(input);
        self.nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the the Glue components belong to the workflow represented as nodes.</p>
    pub fn set_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Node>>) -> Self {
        self.nodes = input;
        self
    }
    /// <p>A list of the the Glue components belong to the workflow represented as nodes.</p>
    pub fn get_nodes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Node>> {
        &self.nodes
    }
    /// Appends an item to `edges`.
    ///
    /// To override the contents of this collection use [`set_edges`](Self::set_edges).
    ///
    /// <p>A list of all the directed connections between the nodes belonging to the workflow.</p>
    pub fn edges(mut self, input: crate::types::Edge) -> Self {
        let mut v = self.edges.unwrap_or_default();
        v.push(input);
        self.edges = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of all the directed connections between the nodes belonging to the workflow.</p>
    pub fn set_edges(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Edge>>) -> Self {
        self.edges = input;
        self
    }
    /// <p>A list of all the directed connections between the nodes belonging to the workflow.</p>
    pub fn get_edges(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Edge>> {
        &self.edges
    }
    /// Consumes the builder and constructs a [`WorkflowGraph`](crate::types::WorkflowGraph).
    pub fn build(self) -> crate::types::WorkflowGraph {
        crate::types::WorkflowGraph {
            nodes: self.nodes,
            edges: self.edges,
        }
    }
}
