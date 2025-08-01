// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The map style options of the geospatial map.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialMapStyleOptions {
    /// <p>The base map style of the geospatial map.</p>
    pub base_map_style: ::std::option::Option<crate::types::BaseMapStyleType>,
}
impl GeospatialMapStyleOptions {
    /// <p>The base map style of the geospatial map.</p>
    pub fn base_map_style(&self) -> ::std::option::Option<&crate::types::BaseMapStyleType> {
        self.base_map_style.as_ref()
    }
}
impl GeospatialMapStyleOptions {
    /// Creates a new builder-style object to manufacture [`GeospatialMapStyleOptions`](crate::types::GeospatialMapStyleOptions).
    pub fn builder() -> crate::types::builders::GeospatialMapStyleOptionsBuilder {
        crate::types::builders::GeospatialMapStyleOptionsBuilder::default()
    }
}

/// A builder for [`GeospatialMapStyleOptions`](crate::types::GeospatialMapStyleOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialMapStyleOptionsBuilder {
    pub(crate) base_map_style: ::std::option::Option<crate::types::BaseMapStyleType>,
}
impl GeospatialMapStyleOptionsBuilder {
    /// <p>The base map style of the geospatial map.</p>
    pub fn base_map_style(mut self, input: crate::types::BaseMapStyleType) -> Self {
        self.base_map_style = ::std::option::Option::Some(input);
        self
    }
    /// <p>The base map style of the geospatial map.</p>
    pub fn set_base_map_style(mut self, input: ::std::option::Option<crate::types::BaseMapStyleType>) -> Self {
        self.base_map_style = input;
        self
    }
    /// <p>The base map style of the geospatial map.</p>
    pub fn get_base_map_style(&self) -> &::std::option::Option<crate::types::BaseMapStyleType> {
        &self.base_map_style
    }
    /// Consumes the builder and constructs a [`GeospatialMapStyleOptions`](crate::types::GeospatialMapStyleOptions).
    pub fn build(self) -> crate::types::GeospatialMapStyleOptions {
        crate::types::GeospatialMapStyleOptions {
            base_map_style: self.base_map_style,
        }
    }
}
