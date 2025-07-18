// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The map definition that defines map state, map style, and geospatial layers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialLayerMapConfiguration {
    /// <p>The options for the legend setup of a visual.</p>
    pub legend: ::std::option::Option<crate::types::LegendOptions>,
    /// <p>The geospatial layers to visualize on the map.</p>
    pub map_layers: ::std::option::Option<::std::vec::Vec<crate::types::GeospatialLayerItem>>,
    /// <p>The map state properties for the map.</p>
    pub map_state: ::std::option::Option<crate::types::GeospatialMapState>,
    /// <p>The map style properties for the map.</p>
    pub map_style: ::std::option::Option<crate::types::GeospatialMapStyle>,
    /// <p>The general visual interactions setup for visual publish options</p>
    pub interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl GeospatialLayerMapConfiguration {
    /// <p>The options for the legend setup of a visual.</p>
    pub fn legend(&self) -> ::std::option::Option<&crate::types::LegendOptions> {
        self.legend.as_ref()
    }
    /// <p>The geospatial layers to visualize on the map.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.map_layers.is_none()`.
    pub fn map_layers(&self) -> &[crate::types::GeospatialLayerItem] {
        self.map_layers.as_deref().unwrap_or_default()
    }
    /// <p>The map state properties for the map.</p>
    pub fn map_state(&self) -> ::std::option::Option<&crate::types::GeospatialMapState> {
        self.map_state.as_ref()
    }
    /// <p>The map style properties for the map.</p>
    pub fn map_style(&self) -> ::std::option::Option<&crate::types::GeospatialMapStyle> {
        self.map_style.as_ref()
    }
    /// <p>The general visual interactions setup for visual publish options</p>
    pub fn interactions(&self) -> ::std::option::Option<&crate::types::VisualInteractionOptions> {
        self.interactions.as_ref()
    }
}
impl GeospatialLayerMapConfiguration {
    /// Creates a new builder-style object to manufacture [`GeospatialLayerMapConfiguration`](crate::types::GeospatialLayerMapConfiguration).
    pub fn builder() -> crate::types::builders::GeospatialLayerMapConfigurationBuilder {
        crate::types::builders::GeospatialLayerMapConfigurationBuilder::default()
    }
}

/// A builder for [`GeospatialLayerMapConfiguration`](crate::types::GeospatialLayerMapConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialLayerMapConfigurationBuilder {
    pub(crate) legend: ::std::option::Option<crate::types::LegendOptions>,
    pub(crate) map_layers: ::std::option::Option<::std::vec::Vec<crate::types::GeospatialLayerItem>>,
    pub(crate) map_state: ::std::option::Option<crate::types::GeospatialMapState>,
    pub(crate) map_style: ::std::option::Option<crate::types::GeospatialMapStyle>,
    pub(crate) interactions: ::std::option::Option<crate::types::VisualInteractionOptions>,
}
impl GeospatialLayerMapConfigurationBuilder {
    /// <p>The options for the legend setup of a visual.</p>
    pub fn legend(mut self, input: crate::types::LegendOptions) -> Self {
        self.legend = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for the legend setup of a visual.</p>
    pub fn set_legend(mut self, input: ::std::option::Option<crate::types::LegendOptions>) -> Self {
        self.legend = input;
        self
    }
    /// <p>The options for the legend setup of a visual.</p>
    pub fn get_legend(&self) -> &::std::option::Option<crate::types::LegendOptions> {
        &self.legend
    }
    /// Appends an item to `map_layers`.
    ///
    /// To override the contents of this collection use [`set_map_layers`](Self::set_map_layers).
    ///
    /// <p>The geospatial layers to visualize on the map.</p>
    pub fn map_layers(mut self, input: crate::types::GeospatialLayerItem) -> Self {
        let mut v = self.map_layers.unwrap_or_default();
        v.push(input);
        self.map_layers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The geospatial layers to visualize on the map.</p>
    pub fn set_map_layers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GeospatialLayerItem>>) -> Self {
        self.map_layers = input;
        self
    }
    /// <p>The geospatial layers to visualize on the map.</p>
    pub fn get_map_layers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GeospatialLayerItem>> {
        &self.map_layers
    }
    /// <p>The map state properties for the map.</p>
    pub fn map_state(mut self, input: crate::types::GeospatialMapState) -> Self {
        self.map_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The map state properties for the map.</p>
    pub fn set_map_state(mut self, input: ::std::option::Option<crate::types::GeospatialMapState>) -> Self {
        self.map_state = input;
        self
    }
    /// <p>The map state properties for the map.</p>
    pub fn get_map_state(&self) -> &::std::option::Option<crate::types::GeospatialMapState> {
        &self.map_state
    }
    /// <p>The map style properties for the map.</p>
    pub fn map_style(mut self, input: crate::types::GeospatialMapStyle) -> Self {
        self.map_style = ::std::option::Option::Some(input);
        self
    }
    /// <p>The map style properties for the map.</p>
    pub fn set_map_style(mut self, input: ::std::option::Option<crate::types::GeospatialMapStyle>) -> Self {
        self.map_style = input;
        self
    }
    /// <p>The map style properties for the map.</p>
    pub fn get_map_style(&self) -> &::std::option::Option<crate::types::GeospatialMapStyle> {
        &self.map_style
    }
    /// <p>The general visual interactions setup for visual publish options</p>
    pub fn interactions(mut self, input: crate::types::VisualInteractionOptions) -> Self {
        self.interactions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The general visual interactions setup for visual publish options</p>
    pub fn set_interactions(mut self, input: ::std::option::Option<crate::types::VisualInteractionOptions>) -> Self {
        self.interactions = input;
        self
    }
    /// <p>The general visual interactions setup for visual publish options</p>
    pub fn get_interactions(&self) -> &::std::option::Option<crate::types::VisualInteractionOptions> {
        &self.interactions
    }
    /// Consumes the builder and constructs a [`GeospatialLayerMapConfiguration`](crate::types::GeospatialLayerMapConfiguration).
    pub fn build(self) -> crate::types::GeospatialLayerMapConfiguration {
        crate::types::GeospatialLayerMapConfiguration {
            legend: self.legend,
            map_layers: self.map_layers,
            map_state: self.map_state,
            map_style: self.map_style,
            interactions: self.interactions,
        }
    }
}
