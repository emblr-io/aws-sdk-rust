// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetNodeOutput {
    /// <p>Properties of the node configuration.</p>
    pub node: ::std::option::Option<crate::types::Node>,
    _request_id: Option<String>,
}
impl GetNodeOutput {
    /// <p>Properties of the node configuration.</p>
    pub fn node(&self) -> ::std::option::Option<&crate::types::Node> {
        self.node.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetNodeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetNodeOutput {
    /// Creates a new builder-style object to manufacture [`GetNodeOutput`](crate::operation::get_node::GetNodeOutput).
    pub fn builder() -> crate::operation::get_node::builders::GetNodeOutputBuilder {
        crate::operation::get_node::builders::GetNodeOutputBuilder::default()
    }
}

/// A builder for [`GetNodeOutput`](crate::operation::get_node::GetNodeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetNodeOutputBuilder {
    pub(crate) node: ::std::option::Option<crate::types::Node>,
    _request_id: Option<String>,
}
impl GetNodeOutputBuilder {
    /// <p>Properties of the node configuration.</p>
    pub fn node(mut self, input: crate::types::Node) -> Self {
        self.node = ::std::option::Option::Some(input);
        self
    }
    /// <p>Properties of the node configuration.</p>
    pub fn set_node(mut self, input: ::std::option::Option<crate::types::Node>) -> Self {
        self.node = input;
        self
    }
    /// <p>Properties of the node configuration.</p>
    pub fn get_node(&self) -> &::std::option::Option<crate::types::Node> {
        &self.node
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetNodeOutput`](crate::operation::get_node::GetNodeOutput).
    pub fn build(self) -> crate::operation::get_node::GetNodeOutput {
        crate::operation::get_node::GetNodeOutput {
            node: self.node,
            _request_id: self._request_id,
        }
    }
}
