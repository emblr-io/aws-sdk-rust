// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an individual node within a DAX cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Node {
    /// <p>A system-generated identifier for the node.</p>
    pub node_id: ::std::option::Option<::std::string::String>,
    /// <p>The endpoint for the node, consisting of a DNS name and a port number. Client applications can connect directly to a node endpoint, if desired (as an alternative to allowing DAX client software to intelligently route requests and responses to nodes in the DAX cluster.</p>
    pub endpoint: ::std::option::Option<crate::types::Endpoint>,
    /// <p>The date and time (in UNIX epoch format) when the node was launched.</p>
    pub node_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Availability Zone (AZ) in which the node has been deployed.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the node. For example: <code>available</code>.</p>
    pub node_status: ::std::option::Option<::std::string::String>,
    /// <p>The status of the parameter group associated with this node. For example, <code>in-sync</code>.</p>
    pub parameter_group_status: ::std::option::Option<::std::string::String>,
}
impl Node {
    /// <p>A system-generated identifier for the node.</p>
    pub fn node_id(&self) -> ::std::option::Option<&str> {
        self.node_id.as_deref()
    }
    /// <p>The endpoint for the node, consisting of a DNS name and a port number. Client applications can connect directly to a node endpoint, if desired (as an alternative to allowing DAX client software to intelligently route requests and responses to nodes in the DAX cluster.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&crate::types::Endpoint> {
        self.endpoint.as_ref()
    }
    /// <p>The date and time (in UNIX epoch format) when the node was launched.</p>
    pub fn node_create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.node_create_time.as_ref()
    }
    /// <p>The Availability Zone (AZ) in which the node has been deployed.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The current status of the node. For example: <code>available</code>.</p>
    pub fn node_status(&self) -> ::std::option::Option<&str> {
        self.node_status.as_deref()
    }
    /// <p>The status of the parameter group associated with this node. For example, <code>in-sync</code>.</p>
    pub fn parameter_group_status(&self) -> ::std::option::Option<&str> {
        self.parameter_group_status.as_deref()
    }
}
impl Node {
    /// Creates a new builder-style object to manufacture [`Node`](crate::types::Node).
    pub fn builder() -> crate::types::builders::NodeBuilder {
        crate::types::builders::NodeBuilder::default()
    }
}

/// A builder for [`Node`](crate::types::Node).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NodeBuilder {
    pub(crate) node_id: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint: ::std::option::Option<crate::types::Endpoint>,
    pub(crate) node_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) node_status: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_group_status: ::std::option::Option<::std::string::String>,
}
impl NodeBuilder {
    /// <p>A system-generated identifier for the node.</p>
    pub fn node_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A system-generated identifier for the node.</p>
    pub fn set_node_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_id = input;
        self
    }
    /// <p>A system-generated identifier for the node.</p>
    pub fn get_node_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_id
    }
    /// <p>The endpoint for the node, consisting of a DNS name and a port number. Client applications can connect directly to a node endpoint, if desired (as an alternative to allowing DAX client software to intelligently route requests and responses to nodes in the DAX cluster.</p>
    pub fn endpoint(mut self, input: crate::types::Endpoint) -> Self {
        self.endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>The endpoint for the node, consisting of a DNS name and a port number. Client applications can connect directly to a node endpoint, if desired (as an alternative to allowing DAX client software to intelligently route requests and responses to nodes in the DAX cluster.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<crate::types::Endpoint>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The endpoint for the node, consisting of a DNS name and a port number. Client applications can connect directly to a node endpoint, if desired (as an alternative to allowing DAX client software to intelligently route requests and responses to nodes in the DAX cluster.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<crate::types::Endpoint> {
        &self.endpoint
    }
    /// <p>The date and time (in UNIX epoch format) when the node was launched.</p>
    pub fn node_create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.node_create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time (in UNIX epoch format) when the node was launched.</p>
    pub fn set_node_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.node_create_time = input;
        self
    }
    /// <p>The date and time (in UNIX epoch format) when the node was launched.</p>
    pub fn get_node_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.node_create_time
    }
    /// <p>The Availability Zone (AZ) in which the node has been deployed.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone (AZ) in which the node has been deployed.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone (AZ) in which the node has been deployed.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The current status of the node. For example: <code>available</code>.</p>
    pub fn node_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current status of the node. For example: <code>available</code>.</p>
    pub fn set_node_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_status = input;
        self
    }
    /// <p>The current status of the node. For example: <code>available</code>.</p>
    pub fn get_node_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_status
    }
    /// <p>The status of the parameter group associated with this node. For example, <code>in-sync</code>.</p>
    pub fn parameter_group_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_group_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the parameter group associated with this node. For example, <code>in-sync</code>.</p>
    pub fn set_parameter_group_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_group_status = input;
        self
    }
    /// <p>The status of the parameter group associated with this node. For example, <code>in-sync</code>.</p>
    pub fn get_parameter_group_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_group_status
    }
    /// Consumes the builder and constructs a [`Node`](crate::types::Node).
    pub fn build(self) -> crate::types::Node {
        crate::types::Node {
            node_id: self.node_id,
            endpoint: self.endpoint,
            node_create_time: self.node_create_time,
            availability_zone: self.availability_zone,
            node_status: self.node_status,
            parameter_group_status: self.parameter_group_status,
        }
    }
}
