// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field wells of a <code>FilledMapVisual</code>.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilledMapFieldWells {
    /// <p>The aggregated field well of the filled map.</p>
    pub filled_map_aggregated_field_wells: ::std::option::Option<crate::types::FilledMapAggregatedFieldWells>,
}
impl FilledMapFieldWells {
    /// <p>The aggregated field well of the filled map.</p>
    pub fn filled_map_aggregated_field_wells(&self) -> ::std::option::Option<&crate::types::FilledMapAggregatedFieldWells> {
        self.filled_map_aggregated_field_wells.as_ref()
    }
}
impl FilledMapFieldWells {
    /// Creates a new builder-style object to manufacture [`FilledMapFieldWells`](crate::types::FilledMapFieldWells).
    pub fn builder() -> crate::types::builders::FilledMapFieldWellsBuilder {
        crate::types::builders::FilledMapFieldWellsBuilder::default()
    }
}

/// A builder for [`FilledMapFieldWells`](crate::types::FilledMapFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilledMapFieldWellsBuilder {
    pub(crate) filled_map_aggregated_field_wells: ::std::option::Option<crate::types::FilledMapAggregatedFieldWells>,
}
impl FilledMapFieldWellsBuilder {
    /// <p>The aggregated field well of the filled map.</p>
    pub fn filled_map_aggregated_field_wells(mut self, input: crate::types::FilledMapAggregatedFieldWells) -> Self {
        self.filled_map_aggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated field well of the filled map.</p>
    pub fn set_filled_map_aggregated_field_wells(mut self, input: ::std::option::Option<crate::types::FilledMapAggregatedFieldWells>) -> Self {
        self.filled_map_aggregated_field_wells = input;
        self
    }
    /// <p>The aggregated field well of the filled map.</p>
    pub fn get_filled_map_aggregated_field_wells(&self) -> &::std::option::Option<crate::types::FilledMapAggregatedFieldWells> {
        &self.filled_map_aggregated_field_wells
    }
    /// Consumes the builder and constructs a [`FilledMapFieldWells`](crate::types::FilledMapFieldWells).
    pub fn build(self) -> crate::types::FilledMapFieldWells {
        crate::types::FilledMapFieldWells {
            filled_map_aggregated_field_wells: self.filled_map_aggregated_field_wells,
        }
    }
}
