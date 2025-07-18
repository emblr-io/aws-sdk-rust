// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The symbol style for null data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialNullSymbolStyle {
    /// <p>The color and opacity values for the fill color.</p>
    pub fill_color: ::std::option::Option<::std::string::String>,
    /// <p>The color and opacity values for the stroke color.</p>
    pub stroke_color: ::std::option::Option<::std::string::String>,
    /// <p>The width of the border stroke.</p>
    pub stroke_width: ::std::option::Option<f64>,
}
impl GeospatialNullSymbolStyle {
    /// <p>The color and opacity values for the fill color.</p>
    pub fn fill_color(&self) -> ::std::option::Option<&str> {
        self.fill_color.as_deref()
    }
    /// <p>The color and opacity values for the stroke color.</p>
    pub fn stroke_color(&self) -> ::std::option::Option<&str> {
        self.stroke_color.as_deref()
    }
    /// <p>The width of the border stroke.</p>
    pub fn stroke_width(&self) -> ::std::option::Option<f64> {
        self.stroke_width
    }
}
impl GeospatialNullSymbolStyle {
    /// Creates a new builder-style object to manufacture [`GeospatialNullSymbolStyle`](crate::types::GeospatialNullSymbolStyle).
    pub fn builder() -> crate::types::builders::GeospatialNullSymbolStyleBuilder {
        crate::types::builders::GeospatialNullSymbolStyleBuilder::default()
    }
}

/// A builder for [`GeospatialNullSymbolStyle`](crate::types::GeospatialNullSymbolStyle).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialNullSymbolStyleBuilder {
    pub(crate) fill_color: ::std::option::Option<::std::string::String>,
    pub(crate) stroke_color: ::std::option::Option<::std::string::String>,
    pub(crate) stroke_width: ::std::option::Option<f64>,
}
impl GeospatialNullSymbolStyleBuilder {
    /// <p>The color and opacity values for the fill color.</p>
    pub fn fill_color(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fill_color = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The color and opacity values for the fill color.</p>
    pub fn set_fill_color(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fill_color = input;
        self
    }
    /// <p>The color and opacity values for the fill color.</p>
    pub fn get_fill_color(&self) -> &::std::option::Option<::std::string::String> {
        &self.fill_color
    }
    /// <p>The color and opacity values for the stroke color.</p>
    pub fn stroke_color(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stroke_color = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The color and opacity values for the stroke color.</p>
    pub fn set_stroke_color(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stroke_color = input;
        self
    }
    /// <p>The color and opacity values for the stroke color.</p>
    pub fn get_stroke_color(&self) -> &::std::option::Option<::std::string::String> {
        &self.stroke_color
    }
    /// <p>The width of the border stroke.</p>
    pub fn stroke_width(mut self, input: f64) -> Self {
        self.stroke_width = ::std::option::Option::Some(input);
        self
    }
    /// <p>The width of the border stroke.</p>
    pub fn set_stroke_width(mut self, input: ::std::option::Option<f64>) -> Self {
        self.stroke_width = input;
        self
    }
    /// <p>The width of the border stroke.</p>
    pub fn get_stroke_width(&self) -> &::std::option::Option<f64> {
        &self.stroke_width
    }
    /// Consumes the builder and constructs a [`GeospatialNullSymbolStyle`](crate::types::GeospatialNullSymbolStyle).
    pub fn build(self) -> crate::types::GeospatialNullSymbolStyle {
        crate::types::GeospatialNullSymbolStyle {
            fill_color: self.fill_color,
            stroke_color: self.stroke_color,
            stroke_width: self.stroke_width,
        }
    }
}
