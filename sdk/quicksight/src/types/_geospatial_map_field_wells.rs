// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field wells of a <code>GeospatialMapVisual</code>.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialMapFieldWells {
    /// <p>The aggregated field well for a geospatial map.</p>
    pub geospatial_map_aggregated_field_wells: ::std::option::Option<crate::types::GeospatialMapAggregatedFieldWells>,
}
impl GeospatialMapFieldWells {
    /// <p>The aggregated field well for a geospatial map.</p>
    pub fn geospatial_map_aggregated_field_wells(&self) -> ::std::option::Option<&crate::types::GeospatialMapAggregatedFieldWells> {
        self.geospatial_map_aggregated_field_wells.as_ref()
    }
}
impl GeospatialMapFieldWells {
    /// Creates a new builder-style object to manufacture [`GeospatialMapFieldWells`](crate::types::GeospatialMapFieldWells).
    pub fn builder() -> crate::types::builders::GeospatialMapFieldWellsBuilder {
        crate::types::builders::GeospatialMapFieldWellsBuilder::default()
    }
}

/// A builder for [`GeospatialMapFieldWells`](crate::types::GeospatialMapFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialMapFieldWellsBuilder {
    pub(crate) geospatial_map_aggregated_field_wells: ::std::option::Option<crate::types::GeospatialMapAggregatedFieldWells>,
}
impl GeospatialMapFieldWellsBuilder {
    /// <p>The aggregated field well for a geospatial map.</p>
    pub fn geospatial_map_aggregated_field_wells(mut self, input: crate::types::GeospatialMapAggregatedFieldWells) -> Self {
        self.geospatial_map_aggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated field well for a geospatial map.</p>
    pub fn set_geospatial_map_aggregated_field_wells(
        mut self,
        input: ::std::option::Option<crate::types::GeospatialMapAggregatedFieldWells>,
    ) -> Self {
        self.geospatial_map_aggregated_field_wells = input;
        self
    }
    /// <p>The aggregated field well for a geospatial map.</p>
    pub fn get_geospatial_map_aggregated_field_wells(&self) -> &::std::option::Option<crate::types::GeospatialMapAggregatedFieldWells> {
        &self.geospatial_map_aggregated_field_wells
    }
    /// Consumes the builder and constructs a [`GeospatialMapFieldWells`](crate::types::GeospatialMapFieldWells).
    pub fn build(self) -> crate::types::GeospatialMapFieldWells {
        crate::types::GeospatialMapFieldWells {
            geospatial_map_aggregated_field_wells: self.geospatial_map_aggregated_field_wells,
        }
    }
}
