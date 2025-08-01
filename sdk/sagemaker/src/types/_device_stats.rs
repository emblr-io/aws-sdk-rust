// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Status of devices.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeviceStats {
    /// <p>The number of devices connected with a heartbeat.</p>
    pub connected_device_count: ::std::option::Option<i64>,
    /// <p>The number of registered devices.</p>
    pub registered_device_count: ::std::option::Option<i64>,
}
impl DeviceStats {
    /// <p>The number of devices connected with a heartbeat.</p>
    pub fn connected_device_count(&self) -> ::std::option::Option<i64> {
        self.connected_device_count
    }
    /// <p>The number of registered devices.</p>
    pub fn registered_device_count(&self) -> ::std::option::Option<i64> {
        self.registered_device_count
    }
}
impl DeviceStats {
    /// Creates a new builder-style object to manufacture [`DeviceStats`](crate::types::DeviceStats).
    pub fn builder() -> crate::types::builders::DeviceStatsBuilder {
        crate::types::builders::DeviceStatsBuilder::default()
    }
}

/// A builder for [`DeviceStats`](crate::types::DeviceStats).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeviceStatsBuilder {
    pub(crate) connected_device_count: ::std::option::Option<i64>,
    pub(crate) registered_device_count: ::std::option::Option<i64>,
}
impl DeviceStatsBuilder {
    /// <p>The number of devices connected with a heartbeat.</p>
    /// This field is required.
    pub fn connected_device_count(mut self, input: i64) -> Self {
        self.connected_device_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of devices connected with a heartbeat.</p>
    pub fn set_connected_device_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.connected_device_count = input;
        self
    }
    /// <p>The number of devices connected with a heartbeat.</p>
    pub fn get_connected_device_count(&self) -> &::std::option::Option<i64> {
        &self.connected_device_count
    }
    /// <p>The number of registered devices.</p>
    /// This field is required.
    pub fn registered_device_count(mut self, input: i64) -> Self {
        self.registered_device_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of registered devices.</p>
    pub fn set_registered_device_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.registered_device_count = input;
        self
    }
    /// <p>The number of registered devices.</p>
    pub fn get_registered_device_count(&self) -> &::std::option::Option<i64> {
        &self.registered_device_count
    }
    /// Consumes the builder and constructs a [`DeviceStats`](crate::types::DeviceStats).
    pub fn build(self) -> crate::types::DeviceStats {
        crate::types::DeviceStats {
            connected_device_count: self.connected_device_count,
            registered_device_count: self.registered_device_count,
        }
    }
}
