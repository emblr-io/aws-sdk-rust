// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NodeExporterInfo {
    /// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
    pub enabled_in_broker: ::std::option::Option<bool>,
}
impl NodeExporterInfo {
    /// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
    pub fn enabled_in_broker(&self) -> ::std::option::Option<bool> {
        self.enabled_in_broker
    }
}
impl NodeExporterInfo {
    /// Creates a new builder-style object to manufacture [`NodeExporterInfo`](crate::types::NodeExporterInfo).
    pub fn builder() -> crate::types::builders::NodeExporterInfoBuilder {
        crate::types::builders::NodeExporterInfoBuilder::default()
    }
}

/// A builder for [`NodeExporterInfo`](crate::types::NodeExporterInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NodeExporterInfoBuilder {
    pub(crate) enabled_in_broker: ::std::option::Option<bool>,
}
impl NodeExporterInfoBuilder {
    /// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
    /// This field is required.
    pub fn enabled_in_broker(mut self, input: bool) -> Self {
        self.enabled_in_broker = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
    pub fn set_enabled_in_broker(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled_in_broker = input;
        self
    }
    /// <p>Indicates whether you want to turn on or turn off the Node Exporter.</p>
    pub fn get_enabled_in_broker(&self) -> &::std::option::Option<bool> {
        &self.enabled_in_broker
    }
    /// Consumes the builder and constructs a [`NodeExporterInfo`](crate::types::NodeExporterInfo).
    pub fn build(self) -> crate::types::NodeExporterInfo {
        crate::types::NodeExporterInfo {
            enabled_in_broker: self.enabled_in_broker,
        }
    }
}
