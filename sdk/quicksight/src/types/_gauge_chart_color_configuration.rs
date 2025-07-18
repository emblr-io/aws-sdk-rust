// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The color configuration of a <code>GaugeChartVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GaugeChartColorConfiguration {
    /// <p>The foreground color configuration of a <code>GaugeChartVisual</code>.</p>
    pub foreground_color: ::std::option::Option<::std::string::String>,
    /// <p>The background color configuration of a <code>GaugeChartVisual</code>.</p>
    pub background_color: ::std::option::Option<::std::string::String>,
}
impl GaugeChartColorConfiguration {
    /// <p>The foreground color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn foreground_color(&self) -> ::std::option::Option<&str> {
        self.foreground_color.as_deref()
    }
    /// <p>The background color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn background_color(&self) -> ::std::option::Option<&str> {
        self.background_color.as_deref()
    }
}
impl GaugeChartColorConfiguration {
    /// Creates a new builder-style object to manufacture [`GaugeChartColorConfiguration`](crate::types::GaugeChartColorConfiguration).
    pub fn builder() -> crate::types::builders::GaugeChartColorConfigurationBuilder {
        crate::types::builders::GaugeChartColorConfigurationBuilder::default()
    }
}

/// A builder for [`GaugeChartColorConfiguration`](crate::types::GaugeChartColorConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GaugeChartColorConfigurationBuilder {
    pub(crate) foreground_color: ::std::option::Option<::std::string::String>,
    pub(crate) background_color: ::std::option::Option<::std::string::String>,
}
impl GaugeChartColorConfigurationBuilder {
    /// <p>The foreground color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn foreground_color(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.foreground_color = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The foreground color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn set_foreground_color(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.foreground_color = input;
        self
    }
    /// <p>The foreground color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn get_foreground_color(&self) -> &::std::option::Option<::std::string::String> {
        &self.foreground_color
    }
    /// <p>The background color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn background_color(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.background_color = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The background color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn set_background_color(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.background_color = input;
        self
    }
    /// <p>The background color configuration of a <code>GaugeChartVisual</code>.</p>
    pub fn get_background_color(&self) -> &::std::option::Option<::std::string::String> {
        &self.background_color
    }
    /// Consumes the builder and constructs a [`GaugeChartColorConfiguration`](crate::types::GaugeChartColorConfiguration).
    pub fn build(self) -> crate::types::GaugeChartColorConfiguration {
        crate::types::GaugeChartColorConfiguration {
            foreground_color: self.foreground_color,
            background_color: self.background_color,
        }
    }
}
