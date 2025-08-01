// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field well configuration of a scatter plot.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScatterPlotFieldWells {
    /// <p>The aggregated field wells of a scatter plot. The x and y-axes of scatter plots with aggregated field wells are aggregated by category, label, or both.</p>
    pub scatter_plot_categorically_aggregated_field_wells: ::std::option::Option<crate::types::ScatterPlotCategoricallyAggregatedFieldWells>,
    /// <p>The unaggregated field wells of a scatter plot. The x and y-axes of these scatter plots are unaggregated.</p>
    pub scatter_plot_unaggregated_field_wells: ::std::option::Option<crate::types::ScatterPlotUnaggregatedFieldWells>,
}
impl ScatterPlotFieldWells {
    /// <p>The aggregated field wells of a scatter plot. The x and y-axes of scatter plots with aggregated field wells are aggregated by category, label, or both.</p>
    pub fn scatter_plot_categorically_aggregated_field_wells(
        &self,
    ) -> ::std::option::Option<&crate::types::ScatterPlotCategoricallyAggregatedFieldWells> {
        self.scatter_plot_categorically_aggregated_field_wells.as_ref()
    }
    /// <p>The unaggregated field wells of a scatter plot. The x and y-axes of these scatter plots are unaggregated.</p>
    pub fn scatter_plot_unaggregated_field_wells(&self) -> ::std::option::Option<&crate::types::ScatterPlotUnaggregatedFieldWells> {
        self.scatter_plot_unaggregated_field_wells.as_ref()
    }
}
impl ScatterPlotFieldWells {
    /// Creates a new builder-style object to manufacture [`ScatterPlotFieldWells`](crate::types::ScatterPlotFieldWells).
    pub fn builder() -> crate::types::builders::ScatterPlotFieldWellsBuilder {
        crate::types::builders::ScatterPlotFieldWellsBuilder::default()
    }
}

/// A builder for [`ScatterPlotFieldWells`](crate::types::ScatterPlotFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScatterPlotFieldWellsBuilder {
    pub(crate) scatter_plot_categorically_aggregated_field_wells: ::std::option::Option<crate::types::ScatterPlotCategoricallyAggregatedFieldWells>,
    pub(crate) scatter_plot_unaggregated_field_wells: ::std::option::Option<crate::types::ScatterPlotUnaggregatedFieldWells>,
}
impl ScatterPlotFieldWellsBuilder {
    /// <p>The aggregated field wells of a scatter plot. The x and y-axes of scatter plots with aggregated field wells are aggregated by category, label, or both.</p>
    pub fn scatter_plot_categorically_aggregated_field_wells(mut self, input: crate::types::ScatterPlotCategoricallyAggregatedFieldWells) -> Self {
        self.scatter_plot_categorically_aggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated field wells of a scatter plot. The x and y-axes of scatter plots with aggregated field wells are aggregated by category, label, or both.</p>
    pub fn set_scatter_plot_categorically_aggregated_field_wells(
        mut self,
        input: ::std::option::Option<crate::types::ScatterPlotCategoricallyAggregatedFieldWells>,
    ) -> Self {
        self.scatter_plot_categorically_aggregated_field_wells = input;
        self
    }
    /// <p>The aggregated field wells of a scatter plot. The x and y-axes of scatter plots with aggregated field wells are aggregated by category, label, or both.</p>
    pub fn get_scatter_plot_categorically_aggregated_field_wells(
        &self,
    ) -> &::std::option::Option<crate::types::ScatterPlotCategoricallyAggregatedFieldWells> {
        &self.scatter_plot_categorically_aggregated_field_wells
    }
    /// <p>The unaggregated field wells of a scatter plot. The x and y-axes of these scatter plots are unaggregated.</p>
    pub fn scatter_plot_unaggregated_field_wells(mut self, input: crate::types::ScatterPlotUnaggregatedFieldWells) -> Self {
        self.scatter_plot_unaggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unaggregated field wells of a scatter plot. The x and y-axes of these scatter plots are unaggregated.</p>
    pub fn set_scatter_plot_unaggregated_field_wells(
        mut self,
        input: ::std::option::Option<crate::types::ScatterPlotUnaggregatedFieldWells>,
    ) -> Self {
        self.scatter_plot_unaggregated_field_wells = input;
        self
    }
    /// <p>The unaggregated field wells of a scatter plot. The x and y-axes of these scatter plots are unaggregated.</p>
    pub fn get_scatter_plot_unaggregated_field_wells(&self) -> &::std::option::Option<crate::types::ScatterPlotUnaggregatedFieldWells> {
        &self.scatter_plot_unaggregated_field_wells
    }
    /// Consumes the builder and constructs a [`ScatterPlotFieldWells`](crate::types::ScatterPlotFieldWells).
    pub fn build(self) -> crate::types::ScatterPlotFieldWells {
        crate::types::ScatterPlotFieldWells {
            scatter_plot_categorically_aggregated_field_wells: self.scatter_plot_categorically_aggregated_field_wells,
            scatter_plot_unaggregated_field_wells: self.scatter_plot_unaggregated_field_wells,
        }
    }
}
