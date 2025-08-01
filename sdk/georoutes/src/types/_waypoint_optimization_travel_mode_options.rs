// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Travel mode related options for the provided travel mode.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WaypointOptimizationTravelModeOptions {
    /// <p>Travel mode options when the provided travel mode is "Pedestrian"</p>
    pub pedestrian: ::std::option::Option<crate::types::WaypointOptimizationPedestrianOptions>,
    /// <p>Travel mode options when the provided travel mode is "Truck"</p>
    pub truck: ::std::option::Option<crate::types::WaypointOptimizationTruckOptions>,
}
impl WaypointOptimizationTravelModeOptions {
    /// <p>Travel mode options when the provided travel mode is "Pedestrian"</p>
    pub fn pedestrian(&self) -> ::std::option::Option<&crate::types::WaypointOptimizationPedestrianOptions> {
        self.pedestrian.as_ref()
    }
    /// <p>Travel mode options when the provided travel mode is "Truck"</p>
    pub fn truck(&self) -> ::std::option::Option<&crate::types::WaypointOptimizationTruckOptions> {
        self.truck.as_ref()
    }
}
impl WaypointOptimizationTravelModeOptions {
    /// Creates a new builder-style object to manufacture [`WaypointOptimizationTravelModeOptions`](crate::types::WaypointOptimizationTravelModeOptions).
    pub fn builder() -> crate::types::builders::WaypointOptimizationTravelModeOptionsBuilder {
        crate::types::builders::WaypointOptimizationTravelModeOptionsBuilder::default()
    }
}

/// A builder for [`WaypointOptimizationTravelModeOptions`](crate::types::WaypointOptimizationTravelModeOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WaypointOptimizationTravelModeOptionsBuilder {
    pub(crate) pedestrian: ::std::option::Option<crate::types::WaypointOptimizationPedestrianOptions>,
    pub(crate) truck: ::std::option::Option<crate::types::WaypointOptimizationTruckOptions>,
}
impl WaypointOptimizationTravelModeOptionsBuilder {
    /// <p>Travel mode options when the provided travel mode is "Pedestrian"</p>
    pub fn pedestrian(mut self, input: crate::types::WaypointOptimizationPedestrianOptions) -> Self {
        self.pedestrian = ::std::option::Option::Some(input);
        self
    }
    /// <p>Travel mode options when the provided travel mode is "Pedestrian"</p>
    pub fn set_pedestrian(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationPedestrianOptions>) -> Self {
        self.pedestrian = input;
        self
    }
    /// <p>Travel mode options when the provided travel mode is "Pedestrian"</p>
    pub fn get_pedestrian(&self) -> &::std::option::Option<crate::types::WaypointOptimizationPedestrianOptions> {
        &self.pedestrian
    }
    /// <p>Travel mode options when the provided travel mode is "Truck"</p>
    pub fn truck(mut self, input: crate::types::WaypointOptimizationTruckOptions) -> Self {
        self.truck = ::std::option::Option::Some(input);
        self
    }
    /// <p>Travel mode options when the provided travel mode is "Truck"</p>
    pub fn set_truck(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationTruckOptions>) -> Self {
        self.truck = input;
        self
    }
    /// <p>Travel mode options when the provided travel mode is "Truck"</p>
    pub fn get_truck(&self) -> &::std::option::Option<crate::types::WaypointOptimizationTruckOptions> {
        &self.truck
    }
    /// Consumes the builder and constructs a [`WaypointOptimizationTravelModeOptions`](crate::types::WaypointOptimizationTravelModeOptions).
    pub fn build(self) -> crate::types::WaypointOptimizationTravelModeOptions {
        crate::types::WaypointOptimizationTravelModeOptions {
            pedestrian: self.pedestrian,
            truck: self.truck,
        }
    }
}
