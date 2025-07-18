// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options that determine the presentation of the <code>GaugeChartVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GaugeChartOptions {
    /// <p>The options that determine the primary value display type.</p>
    pub primary_value_display_type: ::std::option::Option<crate::types::PrimaryValueDisplayType>,
    /// <p>The comparison configuration of a <code>GaugeChartVisual</code>.</p>
    pub comparison: ::std::option::Option<crate::types::ComparisonConfiguration>,
    /// <p>The arc axis configuration of a <code>GaugeChartVisual</code>.</p>
    pub arc_axis: ::std::option::Option<crate::types::ArcAxisConfiguration>,
    /// <p>The arc configuration of a <code>GaugeChartVisual</code>.</p>
    pub arc: ::std::option::Option<crate::types::ArcConfiguration>,
    /// <p>The options that determine the primary value font configuration.</p>
    pub primary_value_font_configuration: ::std::option::Option<crate::types::FontConfiguration>,
}
impl GaugeChartOptions {
    /// <p>The options that determine the primary value display type.</p>
    pub fn primary_value_display_type(&self) -> ::std::option::Option<&crate::types::PrimaryValueDisplayType> {
        self.primary_value_display_type.as_ref()
    }
    /// <p>The comparison configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn comparison(&self) -> ::std::option::Option<&crate::types::ComparisonConfiguration> {
        self.comparison.as_ref()
    }
    /// <p>The arc axis configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn arc_axis(&self) -> ::std::option::Option<&crate::types::ArcAxisConfiguration> {
        self.arc_axis.as_ref()
    }
    /// <p>The arc configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn arc(&self) -> ::std::option::Option<&crate::types::ArcConfiguration> {
        self.arc.as_ref()
    }
    /// <p>The options that determine the primary value font configuration.</p>
    pub fn primary_value_font_configuration(&self) -> ::std::option::Option<&crate::types::FontConfiguration> {
        self.primary_value_font_configuration.as_ref()
    }
}
impl GaugeChartOptions {
    /// Creates a new builder-style object to manufacture [`GaugeChartOptions`](crate::types::GaugeChartOptions).
    pub fn builder() -> crate::types::builders::GaugeChartOptionsBuilder {
        crate::types::builders::GaugeChartOptionsBuilder::default()
    }
}

/// A builder for [`GaugeChartOptions`](crate::types::GaugeChartOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GaugeChartOptionsBuilder {
    pub(crate) primary_value_display_type: ::std::option::Option<crate::types::PrimaryValueDisplayType>,
    pub(crate) comparison: ::std::option::Option<crate::types::ComparisonConfiguration>,
    pub(crate) arc_axis: ::std::option::Option<crate::types::ArcAxisConfiguration>,
    pub(crate) arc: ::std::option::Option<crate::types::ArcConfiguration>,
    pub(crate) primary_value_font_configuration: ::std::option::Option<crate::types::FontConfiguration>,
}
impl GaugeChartOptionsBuilder {
    /// <p>The options that determine the primary value display type.</p>
    pub fn primary_value_display_type(mut self, input: crate::types::PrimaryValueDisplayType) -> Self {
        self.primary_value_display_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the primary value display type.</p>
    pub fn set_primary_value_display_type(mut self, input: ::std::option::Option<crate::types::PrimaryValueDisplayType>) -> Self {
        self.primary_value_display_type = input;
        self
    }
    /// <p>The options that determine the primary value display type.</p>
    pub fn get_primary_value_display_type(&self) -> &::std::option::Option<crate::types::PrimaryValueDisplayType> {
        &self.primary_value_display_type
    }
    /// <p>The comparison configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn comparison(mut self, input: crate::types::ComparisonConfiguration) -> Self {
        self.comparison = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn set_comparison(mut self, input: ::std::option::Option<crate::types::ComparisonConfiguration>) -> Self {
        self.comparison = input;
        self
    }
    /// <p>The comparison configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn get_comparison(&self) -> &::std::option::Option<crate::types::ComparisonConfiguration> {
        &self.comparison
    }
    /// <p>The arc axis configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn arc_axis(mut self, input: crate::types::ArcAxisConfiguration) -> Self {
        self.arc_axis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The arc axis configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn set_arc_axis(mut self, input: ::std::option::Option<crate::types::ArcAxisConfiguration>) -> Self {
        self.arc_axis = input;
        self
    }
    /// <p>The arc axis configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn get_arc_axis(&self) -> &::std::option::Option<crate::types::ArcAxisConfiguration> {
        &self.arc_axis
    }
    /// <p>The arc configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn arc(mut self, input: crate::types::ArcConfiguration) -> Self {
        self.arc = ::std::option::Option::Some(input);
        self
    }
    /// <p>The arc configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn set_arc(mut self, input: ::std::option::Option<crate::types::ArcConfiguration>) -> Self {
        self.arc = input;
        self
    }
    /// <p>The arc configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn get_arc(&self) -> &::std::option::Option<crate::types::ArcConfiguration> {
        &self.arc
    }
    /// <p>The options that determine the primary value font configuration.</p>
    pub fn primary_value_font_configuration(mut self, input: crate::types::FontConfiguration) -> Self {
        self.primary_value_font_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the primary value font configuration.</p>
    pub fn set_primary_value_font_configuration(mut self, input: ::std::option::Option<crate::types::FontConfiguration>) -> Self {
        self.primary_value_font_configuration = input;
        self
    }
    /// <p>The options that determine the primary value font configuration.</p>
    pub fn get_primary_value_font_configuration(&self) -> &::std::option::Option<crate::types::FontConfiguration> {
        &self.primary_value_font_configuration
    }
    /// Consumes the builder and constructs a [`GaugeChartOptions`](crate::types::GaugeChartOptions).
    pub fn build(self) -> crate::types::GaugeChartOptions {
        crate::types::GaugeChartOptions {
            primary_value_display_type: self.primary_value_display_type,
            comparison: self.comparison,
            arc_axis: self.arc_axis,
            arc: self.arc,
            primary_value_font_configuration: self.primary_value_font_configuration,
        }
    }
}
