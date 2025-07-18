// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateScriptInput {
    /// <p>A list of the nodes in the DAG.</p>
    pub dag_nodes: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenNode>>,
    /// <p>A list of the edges in the DAG.</p>
    pub dag_edges: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenEdge>>,
    /// <p>The programming language of the resulting code from the DAG.</p>
    pub language: ::std::option::Option<crate::types::Language>,
}
impl CreateScriptInput {
    /// <p>A list of the nodes in the DAG.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dag_nodes.is_none()`.
    pub fn dag_nodes(&self) -> &[crate::types::CodeGenNode] {
        self.dag_nodes.as_deref().unwrap_or_default()
    }
    /// <p>A list of the edges in the DAG.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dag_edges.is_none()`.
    pub fn dag_edges(&self) -> &[crate::types::CodeGenEdge] {
        self.dag_edges.as_deref().unwrap_or_default()
    }
    /// <p>The programming language of the resulting code from the DAG.</p>
    pub fn language(&self) -> ::std::option::Option<&crate::types::Language> {
        self.language.as_ref()
    }
}
impl CreateScriptInput {
    /// Creates a new builder-style object to manufacture [`CreateScriptInput`](crate::operation::create_script::CreateScriptInput).
    pub fn builder() -> crate::operation::create_script::builders::CreateScriptInputBuilder {
        crate::operation::create_script::builders::CreateScriptInputBuilder::default()
    }
}

/// A builder for [`CreateScriptInput`](crate::operation::create_script::CreateScriptInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateScriptInputBuilder {
    pub(crate) dag_nodes: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenNode>>,
    pub(crate) dag_edges: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenEdge>>,
    pub(crate) language: ::std::option::Option<crate::types::Language>,
}
impl CreateScriptInputBuilder {
    /// Appends an item to `dag_nodes`.
    ///
    /// To override the contents of this collection use [`set_dag_nodes`](Self::set_dag_nodes).
    ///
    /// <p>A list of the nodes in the DAG.</p>
    pub fn dag_nodes(mut self, input: crate::types::CodeGenNode) -> Self {
        let mut v = self.dag_nodes.unwrap_or_default();
        v.push(input);
        self.dag_nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the nodes in the DAG.</p>
    pub fn set_dag_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenNode>>) -> Self {
        self.dag_nodes = input;
        self
    }
    /// <p>A list of the nodes in the DAG.</p>
    pub fn get_dag_nodes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CodeGenNode>> {
        &self.dag_nodes
    }
    /// Appends an item to `dag_edges`.
    ///
    /// To override the contents of this collection use [`set_dag_edges`](Self::set_dag_edges).
    ///
    /// <p>A list of the edges in the DAG.</p>
    pub fn dag_edges(mut self, input: crate::types::CodeGenEdge) -> Self {
        let mut v = self.dag_edges.unwrap_or_default();
        v.push(input);
        self.dag_edges = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the edges in the DAG.</p>
    pub fn set_dag_edges(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CodeGenEdge>>) -> Self {
        self.dag_edges = input;
        self
    }
    /// <p>A list of the edges in the DAG.</p>
    pub fn get_dag_edges(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CodeGenEdge>> {
        &self.dag_edges
    }
    /// <p>The programming language of the resulting code from the DAG.</p>
    pub fn language(mut self, input: crate::types::Language) -> Self {
        self.language = ::std::option::Option::Some(input);
        self
    }
    /// <p>The programming language of the resulting code from the DAG.</p>
    pub fn set_language(mut self, input: ::std::option::Option<crate::types::Language>) -> Self {
        self.language = input;
        self
    }
    /// <p>The programming language of the resulting code from the DAG.</p>
    pub fn get_language(&self) -> &::std::option::Option<crate::types::Language> {
        &self.language
    }
    /// Consumes the builder and constructs a [`CreateScriptInput`](crate::operation::create_script::CreateScriptInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_script::CreateScriptInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_script::CreateScriptInput {
            dag_nodes: self.dag_nodes,
            dag_edges: self.dag_edges,
            language: self.language,
        })
    }
}
