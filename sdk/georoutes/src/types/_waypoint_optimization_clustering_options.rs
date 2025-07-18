// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options for WaypointOptimizationClustering.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WaypointOptimizationClusteringOptions {
    /// <p>The algorithm to be used. <code>DrivingDistance</code> assigns all the waypoints that are within driving distance of each other into a single cluster. <code>TopologySegment</code> assigns all the waypoints that are within the same topology segment into a single cluster. A Topology segment is a linear stretch of road between two junctions.</p>
    pub algorithm: crate::types::WaypointOptimizationClusteringAlgorithm,
    /// <p>Driving distance options to be used when the clustering algorithm is DrivingDistance.</p>
    pub driving_distance_options: ::std::option::Option<crate::types::WaypointOptimizationDrivingDistanceOptions>,
}
impl WaypointOptimizationClusteringOptions {
    /// <p>The algorithm to be used. <code>DrivingDistance</code> assigns all the waypoints that are within driving distance of each other into a single cluster. <code>TopologySegment</code> assigns all the waypoints that are within the same topology segment into a single cluster. A Topology segment is a linear stretch of road between two junctions.</p>
    pub fn algorithm(&self) -> &crate::types::WaypointOptimizationClusteringAlgorithm {
        &self.algorithm
    }
    /// <p>Driving distance options to be used when the clustering algorithm is DrivingDistance.</p>
    pub fn driving_distance_options(&self) -> ::std::option::Option<&crate::types::WaypointOptimizationDrivingDistanceOptions> {
        self.driving_distance_options.as_ref()
    }
}
impl WaypointOptimizationClusteringOptions {
    /// Creates a new builder-style object to manufacture [`WaypointOptimizationClusteringOptions`](crate::types::WaypointOptimizationClusteringOptions).
    pub fn builder() -> crate::types::builders::WaypointOptimizationClusteringOptionsBuilder {
        crate::types::builders::WaypointOptimizationClusteringOptionsBuilder::default()
    }
}

/// A builder for [`WaypointOptimizationClusteringOptions`](crate::types::WaypointOptimizationClusteringOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WaypointOptimizationClusteringOptionsBuilder {
    pub(crate) algorithm: ::std::option::Option<crate::types::WaypointOptimizationClusteringAlgorithm>,
    pub(crate) driving_distance_options: ::std::option::Option<crate::types::WaypointOptimizationDrivingDistanceOptions>,
}
impl WaypointOptimizationClusteringOptionsBuilder {
    /// <p>The algorithm to be used. <code>DrivingDistance</code> assigns all the waypoints that are within driving distance of each other into a single cluster. <code>TopologySegment</code> assigns all the waypoints that are within the same topology segment into a single cluster. A Topology segment is a linear stretch of road between two junctions.</p>
    /// This field is required.
    pub fn algorithm(mut self, input: crate::types::WaypointOptimizationClusteringAlgorithm) -> Self {
        self.algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>The algorithm to be used. <code>DrivingDistance</code> assigns all the waypoints that are within driving distance of each other into a single cluster. <code>TopologySegment</code> assigns all the waypoints that are within the same topology segment into a single cluster. A Topology segment is a linear stretch of road between two junctions.</p>
    pub fn set_algorithm(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationClusteringAlgorithm>) -> Self {
        self.algorithm = input;
        self
    }
    /// <p>The algorithm to be used. <code>DrivingDistance</code> assigns all the waypoints that are within driving distance of each other into a single cluster. <code>TopologySegment</code> assigns all the waypoints that are within the same topology segment into a single cluster. A Topology segment is a linear stretch of road between two junctions.</p>
    pub fn get_algorithm(&self) -> &::std::option::Option<crate::types::WaypointOptimizationClusteringAlgorithm> {
        &self.algorithm
    }
    /// <p>Driving distance options to be used when the clustering algorithm is DrivingDistance.</p>
    pub fn driving_distance_options(mut self, input: crate::types::WaypointOptimizationDrivingDistanceOptions) -> Self {
        self.driving_distance_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Driving distance options to be used when the clustering algorithm is DrivingDistance.</p>
    pub fn set_driving_distance_options(mut self, input: ::std::option::Option<crate::types::WaypointOptimizationDrivingDistanceOptions>) -> Self {
        self.driving_distance_options = input;
        self
    }
    /// <p>Driving distance options to be used when the clustering algorithm is DrivingDistance.</p>
    pub fn get_driving_distance_options(&self) -> &::std::option::Option<crate::types::WaypointOptimizationDrivingDistanceOptions> {
        &self.driving_distance_options
    }
    /// Consumes the builder and constructs a [`WaypointOptimizationClusteringOptions`](crate::types::WaypointOptimizationClusteringOptions).
    /// This method will fail if any of the following fields are not set:
    /// - [`algorithm`](crate::types::builders::WaypointOptimizationClusteringOptionsBuilder::algorithm)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::WaypointOptimizationClusteringOptions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WaypointOptimizationClusteringOptions {
            algorithm: self.algorithm.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "algorithm",
                    "algorithm was not specified but it is required when building WaypointOptimizationClusteringOptions",
                )
            })?,
            driving_distance_options: self.driving_distance_options,
        })
    }
}
