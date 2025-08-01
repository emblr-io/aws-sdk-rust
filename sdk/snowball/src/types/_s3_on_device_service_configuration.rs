// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Amazon S3 compatible storage on Snow family devices configuration items.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3OnDeviceServiceConfiguration {
    /// <p>If the specified storage limit value matches storage limit of one of the defined configurations, that configuration will be used. If the specified storage limit value does not match any defined configuration, the request will fail. If more than one configuration has the same storage limit as specified, the other input need to be provided.</p>
    pub storage_limit: ::std::option::Option<f64>,
    /// <p>Storage unit. Currently the only supported unit is TB.</p>
    pub storage_unit: ::std::option::Option<crate::types::StorageUnit>,
    /// <p>Applicable when creating a cluster. Specifies how many nodes are needed for Amazon S3 compatible storage on Snow family devices. If specified, the other input can be omitted.</p>
    pub service_size: ::std::option::Option<i32>,
    /// <p>&gt;Fault tolerance level of the cluster. This indicates the number of nodes that can go down without degrading the performance of the cluster. This additional input helps when the specified <code>StorageLimit</code> matches more than one Amazon S3 compatible storage on Snow family devices service configuration.</p>
    pub fault_tolerance: ::std::option::Option<i32>,
}
impl S3OnDeviceServiceConfiguration {
    /// <p>If the specified storage limit value matches storage limit of one of the defined configurations, that configuration will be used. If the specified storage limit value does not match any defined configuration, the request will fail. If more than one configuration has the same storage limit as specified, the other input need to be provided.</p>
    pub fn storage_limit(&self) -> ::std::option::Option<f64> {
        self.storage_limit
    }
    /// <p>Storage unit. Currently the only supported unit is TB.</p>
    pub fn storage_unit(&self) -> ::std::option::Option<&crate::types::StorageUnit> {
        self.storage_unit.as_ref()
    }
    /// <p>Applicable when creating a cluster. Specifies how many nodes are needed for Amazon S3 compatible storage on Snow family devices. If specified, the other input can be omitted.</p>
    pub fn service_size(&self) -> ::std::option::Option<i32> {
        self.service_size
    }
    /// <p>&gt;Fault tolerance level of the cluster. This indicates the number of nodes that can go down without degrading the performance of the cluster. This additional input helps when the specified <code>StorageLimit</code> matches more than one Amazon S3 compatible storage on Snow family devices service configuration.</p>
    pub fn fault_tolerance(&self) -> ::std::option::Option<i32> {
        self.fault_tolerance
    }
}
impl S3OnDeviceServiceConfiguration {
    /// Creates a new builder-style object to manufacture [`S3OnDeviceServiceConfiguration`](crate::types::S3OnDeviceServiceConfiguration).
    pub fn builder() -> crate::types::builders::S3OnDeviceServiceConfigurationBuilder {
        crate::types::builders::S3OnDeviceServiceConfigurationBuilder::default()
    }
}

/// A builder for [`S3OnDeviceServiceConfiguration`](crate::types::S3OnDeviceServiceConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3OnDeviceServiceConfigurationBuilder {
    pub(crate) storage_limit: ::std::option::Option<f64>,
    pub(crate) storage_unit: ::std::option::Option<crate::types::StorageUnit>,
    pub(crate) service_size: ::std::option::Option<i32>,
    pub(crate) fault_tolerance: ::std::option::Option<i32>,
}
impl S3OnDeviceServiceConfigurationBuilder {
    /// <p>If the specified storage limit value matches storage limit of one of the defined configurations, that configuration will be used. If the specified storage limit value does not match any defined configuration, the request will fail. If more than one configuration has the same storage limit as specified, the other input need to be provided.</p>
    pub fn storage_limit(mut self, input: f64) -> Self {
        self.storage_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the specified storage limit value matches storage limit of one of the defined configurations, that configuration will be used. If the specified storage limit value does not match any defined configuration, the request will fail. If more than one configuration has the same storage limit as specified, the other input need to be provided.</p>
    pub fn set_storage_limit(mut self, input: ::std::option::Option<f64>) -> Self {
        self.storage_limit = input;
        self
    }
    /// <p>If the specified storage limit value matches storage limit of one of the defined configurations, that configuration will be used. If the specified storage limit value does not match any defined configuration, the request will fail. If more than one configuration has the same storage limit as specified, the other input need to be provided.</p>
    pub fn get_storage_limit(&self) -> &::std::option::Option<f64> {
        &self.storage_limit
    }
    /// <p>Storage unit. Currently the only supported unit is TB.</p>
    pub fn storage_unit(mut self, input: crate::types::StorageUnit) -> Self {
        self.storage_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Storage unit. Currently the only supported unit is TB.</p>
    pub fn set_storage_unit(mut self, input: ::std::option::Option<crate::types::StorageUnit>) -> Self {
        self.storage_unit = input;
        self
    }
    /// <p>Storage unit. Currently the only supported unit is TB.</p>
    pub fn get_storage_unit(&self) -> &::std::option::Option<crate::types::StorageUnit> {
        &self.storage_unit
    }
    /// <p>Applicable when creating a cluster. Specifies how many nodes are needed for Amazon S3 compatible storage on Snow family devices. If specified, the other input can be omitted.</p>
    pub fn service_size(mut self, input: i32) -> Self {
        self.service_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Applicable when creating a cluster. Specifies how many nodes are needed for Amazon S3 compatible storage on Snow family devices. If specified, the other input can be omitted.</p>
    pub fn set_service_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.service_size = input;
        self
    }
    /// <p>Applicable when creating a cluster. Specifies how many nodes are needed for Amazon S3 compatible storage on Snow family devices. If specified, the other input can be omitted.</p>
    pub fn get_service_size(&self) -> &::std::option::Option<i32> {
        &self.service_size
    }
    /// <p>&gt;Fault tolerance level of the cluster. This indicates the number of nodes that can go down without degrading the performance of the cluster. This additional input helps when the specified <code>StorageLimit</code> matches more than one Amazon S3 compatible storage on Snow family devices service configuration.</p>
    pub fn fault_tolerance(mut self, input: i32) -> Self {
        self.fault_tolerance = ::std::option::Option::Some(input);
        self
    }
    /// <p>&gt;Fault tolerance level of the cluster. This indicates the number of nodes that can go down without degrading the performance of the cluster. This additional input helps when the specified <code>StorageLimit</code> matches more than one Amazon S3 compatible storage on Snow family devices service configuration.</p>
    pub fn set_fault_tolerance(mut self, input: ::std::option::Option<i32>) -> Self {
        self.fault_tolerance = input;
        self
    }
    /// <p>&gt;Fault tolerance level of the cluster. This indicates the number of nodes that can go down without degrading the performance of the cluster. This additional input helps when the specified <code>StorageLimit</code> matches more than one Amazon S3 compatible storage on Snow family devices service configuration.</p>
    pub fn get_fault_tolerance(&self) -> &::std::option::Option<i32> {
        &self.fault_tolerance
    }
    /// Consumes the builder and constructs a [`S3OnDeviceServiceConfiguration`](crate::types::S3OnDeviceServiceConfiguration).
    pub fn build(self) -> crate::types::S3OnDeviceServiceConfiguration {
        crate::types::S3OnDeviceServiceConfiguration {
            storage_limit: self.storage_limit,
            storage_unit: self.storage_unit,
            service_size: self.service_size,
            fault_tolerance: self.fault_tolerance,
        }
    }
}
