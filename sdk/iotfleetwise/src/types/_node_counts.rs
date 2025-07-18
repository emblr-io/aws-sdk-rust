// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the number of nodes and node types in a vehicle network.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NodeCounts {
    /// <p>The total number of nodes in a vehicle network.</p>
    pub total_nodes: i32,
    /// <p>The total number of nodes in a vehicle network that represent branches.</p>
    pub total_branches: i32,
    /// <p>The total number of nodes in a vehicle network that represent sensors.</p>
    pub total_sensors: i32,
    /// <p>The total number of nodes in a vehicle network that represent attributes.</p>
    pub total_attributes: i32,
    /// <p>The total number of nodes in a vehicle network that represent actuators.</p>
    pub total_actuators: i32,
    /// <p>The total structure for the node.</p>
    pub total_structs: i32,
    /// <p>The total properties for the node.</p>
    pub total_properties: i32,
}
impl NodeCounts {
    /// <p>The total number of nodes in a vehicle network.</p>
    pub fn total_nodes(&self) -> i32 {
        self.total_nodes
    }
    /// <p>The total number of nodes in a vehicle network that represent branches.</p>
    pub fn total_branches(&self) -> i32 {
        self.total_branches
    }
    /// <p>The total number of nodes in a vehicle network that represent sensors.</p>
    pub fn total_sensors(&self) -> i32 {
        self.total_sensors
    }
    /// <p>The total number of nodes in a vehicle network that represent attributes.</p>
    pub fn total_attributes(&self) -> i32 {
        self.total_attributes
    }
    /// <p>The total number of nodes in a vehicle network that represent actuators.</p>
    pub fn total_actuators(&self) -> i32 {
        self.total_actuators
    }
    /// <p>The total structure for the node.</p>
    pub fn total_structs(&self) -> i32 {
        self.total_structs
    }
    /// <p>The total properties for the node.</p>
    pub fn total_properties(&self) -> i32 {
        self.total_properties
    }
}
impl NodeCounts {
    /// Creates a new builder-style object to manufacture [`NodeCounts`](crate::types::NodeCounts).
    pub fn builder() -> crate::types::builders::NodeCountsBuilder {
        crate::types::builders::NodeCountsBuilder::default()
    }
}

/// A builder for [`NodeCounts`](crate::types::NodeCounts).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NodeCountsBuilder {
    pub(crate) total_nodes: ::std::option::Option<i32>,
    pub(crate) total_branches: ::std::option::Option<i32>,
    pub(crate) total_sensors: ::std::option::Option<i32>,
    pub(crate) total_attributes: ::std::option::Option<i32>,
    pub(crate) total_actuators: ::std::option::Option<i32>,
    pub(crate) total_structs: ::std::option::Option<i32>,
    pub(crate) total_properties: ::std::option::Option<i32>,
}
impl NodeCountsBuilder {
    /// <p>The total number of nodes in a vehicle network.</p>
    pub fn total_nodes(mut self, input: i32) -> Self {
        self.total_nodes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of nodes in a vehicle network.</p>
    pub fn set_total_nodes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_nodes = input;
        self
    }
    /// <p>The total number of nodes in a vehicle network.</p>
    pub fn get_total_nodes(&self) -> &::std::option::Option<i32> {
        &self.total_nodes
    }
    /// <p>The total number of nodes in a vehicle network that represent branches.</p>
    pub fn total_branches(mut self, input: i32) -> Self {
        self.total_branches = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent branches.</p>
    pub fn set_total_branches(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_branches = input;
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent branches.</p>
    pub fn get_total_branches(&self) -> &::std::option::Option<i32> {
        &self.total_branches
    }
    /// <p>The total number of nodes in a vehicle network that represent sensors.</p>
    pub fn total_sensors(mut self, input: i32) -> Self {
        self.total_sensors = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent sensors.</p>
    pub fn set_total_sensors(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_sensors = input;
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent sensors.</p>
    pub fn get_total_sensors(&self) -> &::std::option::Option<i32> {
        &self.total_sensors
    }
    /// <p>The total number of nodes in a vehicle network that represent attributes.</p>
    pub fn total_attributes(mut self, input: i32) -> Self {
        self.total_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent attributes.</p>
    pub fn set_total_attributes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_attributes = input;
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent attributes.</p>
    pub fn get_total_attributes(&self) -> &::std::option::Option<i32> {
        &self.total_attributes
    }
    /// <p>The total number of nodes in a vehicle network that represent actuators.</p>
    pub fn total_actuators(mut self, input: i32) -> Self {
        self.total_actuators = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent actuators.</p>
    pub fn set_total_actuators(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_actuators = input;
        self
    }
    /// <p>The total number of nodes in a vehicle network that represent actuators.</p>
    pub fn get_total_actuators(&self) -> &::std::option::Option<i32> {
        &self.total_actuators
    }
    /// <p>The total structure for the node.</p>
    pub fn total_structs(mut self, input: i32) -> Self {
        self.total_structs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total structure for the node.</p>
    pub fn set_total_structs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_structs = input;
        self
    }
    /// <p>The total structure for the node.</p>
    pub fn get_total_structs(&self) -> &::std::option::Option<i32> {
        &self.total_structs
    }
    /// <p>The total properties for the node.</p>
    pub fn total_properties(mut self, input: i32) -> Self {
        self.total_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total properties for the node.</p>
    pub fn set_total_properties(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_properties = input;
        self
    }
    /// <p>The total properties for the node.</p>
    pub fn get_total_properties(&self) -> &::std::option::Option<i32> {
        &self.total_properties
    }
    /// Consumes the builder and constructs a [`NodeCounts`](crate::types::NodeCounts).
    pub fn build(self) -> crate::types::NodeCounts {
        crate::types::NodeCounts {
            total_nodes: self.total_nodes.unwrap_or_default(),
            total_branches: self.total_branches.unwrap_or_default(),
            total_sensors: self.total_sensors.unwrap_or_default(),
            total_attributes: self.total_attributes.unwrap_or_default(),
            total_actuators: self.total_actuators.unwrap_or_default(),
            total_structs: self.total_structs.unwrap_or_default(),
            total_properties: self.total_properties.unwrap_or_default(),
        }
    }
}
