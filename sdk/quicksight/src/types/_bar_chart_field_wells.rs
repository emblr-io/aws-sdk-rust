// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field wells of a <code>BarChartVisual</code>.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BarChartFieldWells {
    /// <p>The aggregated field wells of a bar chart.</p>
    pub bar_chart_aggregated_field_wells: ::std::option::Option<crate::types::BarChartAggregatedFieldWells>,
}
impl BarChartFieldWells {
    /// <p>The aggregated field wells of a bar chart.</p>
    pub fn bar_chart_aggregated_field_wells(&self) -> ::std::option::Option<&crate::types::BarChartAggregatedFieldWells> {
        self.bar_chart_aggregated_field_wells.as_ref()
    }
}
impl BarChartFieldWells {
    /// Creates a new builder-style object to manufacture [`BarChartFieldWells`](crate::types::BarChartFieldWells).
    pub fn builder() -> crate::types::builders::BarChartFieldWellsBuilder {
        crate::types::builders::BarChartFieldWellsBuilder::default()
    }
}

/// A builder for [`BarChartFieldWells`](crate::types::BarChartFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BarChartFieldWellsBuilder {
    pub(crate) bar_chart_aggregated_field_wells: ::std::option::Option<crate::types::BarChartAggregatedFieldWells>,
}
impl BarChartFieldWellsBuilder {
    /// <p>The aggregated field wells of a bar chart.</p>
    pub fn bar_chart_aggregated_field_wells(mut self, input: crate::types::BarChartAggregatedFieldWells) -> Self {
        self.bar_chart_aggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated field wells of a bar chart.</p>
    pub fn set_bar_chart_aggregated_field_wells(mut self, input: ::std::option::Option<crate::types::BarChartAggregatedFieldWells>) -> Self {
        self.bar_chart_aggregated_field_wells = input;
        self
    }
    /// <p>The aggregated field wells of a bar chart.</p>
    pub fn get_bar_chart_aggregated_field_wells(&self) -> &::std::option::Option<crate::types::BarChartAggregatedFieldWells> {
        &self.bar_chart_aggregated_field_wells
    }
    /// Consumes the builder and constructs a [`BarChartFieldWells`](crate::types::BarChartFieldWells).
    pub fn build(self) -> crate::types::BarChartFieldWells {
        crate::types::BarChartFieldWells {
            bar_chart_aggregated_field_wells: self.bar_chart_aggregated_field_wells,
        }
    }
}
