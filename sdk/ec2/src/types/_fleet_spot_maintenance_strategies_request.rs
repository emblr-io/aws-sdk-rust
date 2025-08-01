// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The strategies for managing your Spot Instances that are at an elevated risk of being interrupted.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FleetSpotMaintenanceStrategiesRequest {
    /// <p>The strategy to use when Amazon EC2 emits a signal that your Spot Instance is at an elevated risk of being interrupted.</p>
    pub capacity_rebalance: ::std::option::Option<crate::types::FleetSpotCapacityRebalanceRequest>,
}
impl FleetSpotMaintenanceStrategiesRequest {
    /// <p>The strategy to use when Amazon EC2 emits a signal that your Spot Instance is at an elevated risk of being interrupted.</p>
    pub fn capacity_rebalance(&self) -> ::std::option::Option<&crate::types::FleetSpotCapacityRebalanceRequest> {
        self.capacity_rebalance.as_ref()
    }
}
impl FleetSpotMaintenanceStrategiesRequest {
    /// Creates a new builder-style object to manufacture [`FleetSpotMaintenanceStrategiesRequest`](crate::types::FleetSpotMaintenanceStrategiesRequest).
    pub fn builder() -> crate::types::builders::FleetSpotMaintenanceStrategiesRequestBuilder {
        crate::types::builders::FleetSpotMaintenanceStrategiesRequestBuilder::default()
    }
}

/// A builder for [`FleetSpotMaintenanceStrategiesRequest`](crate::types::FleetSpotMaintenanceStrategiesRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FleetSpotMaintenanceStrategiesRequestBuilder {
    pub(crate) capacity_rebalance: ::std::option::Option<crate::types::FleetSpotCapacityRebalanceRequest>,
}
impl FleetSpotMaintenanceStrategiesRequestBuilder {
    /// <p>The strategy to use when Amazon EC2 emits a signal that your Spot Instance is at an elevated risk of being interrupted.</p>
    pub fn capacity_rebalance(mut self, input: crate::types::FleetSpotCapacityRebalanceRequest) -> Self {
        self.capacity_rebalance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The strategy to use when Amazon EC2 emits a signal that your Spot Instance is at an elevated risk of being interrupted.</p>
    pub fn set_capacity_rebalance(mut self, input: ::std::option::Option<crate::types::FleetSpotCapacityRebalanceRequest>) -> Self {
        self.capacity_rebalance = input;
        self
    }
    /// <p>The strategy to use when Amazon EC2 emits a signal that your Spot Instance is at an elevated risk of being interrupted.</p>
    pub fn get_capacity_rebalance(&self) -> &::std::option::Option<crate::types::FleetSpotCapacityRebalanceRequest> {
        &self.capacity_rebalance
    }
    /// Consumes the builder and constructs a [`FleetSpotMaintenanceStrategiesRequest`](crate::types::FleetSpotMaintenanceStrategiesRequest).
    pub fn build(self) -> crate::types::FleetSpotMaintenanceStrategiesRequest {
        crate::types::FleetSpotMaintenanceStrategiesRequest {
            capacity_rebalance: self.capacity_rebalance,
        }
    }
}
