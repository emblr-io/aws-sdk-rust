// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the configuration settings for the horizontal layout.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HorizontalLayoutConfiguration {
    /// <p>Sets the automatic ordering of the video tiles.</p>
    pub tile_order: ::std::option::Option<crate::types::TileOrder>,
    /// <p>Sets the position of horizontal tiles.</p>
    pub tile_position: ::std::option::Option<crate::types::HorizontalTilePosition>,
    /// <p>The maximum number of video tiles to display.</p>
    pub tile_count: ::std::option::Option<i32>,
    /// <p>Specifies the aspect ratio of all video tiles.</p>
    pub tile_aspect_ratio: ::std::option::Option<::std::string::String>,
}
impl HorizontalLayoutConfiguration {
    /// <p>Sets the automatic ordering of the video tiles.</p>
    pub fn tile_order(&self) -> ::std::option::Option<&crate::types::TileOrder> {
        self.tile_order.as_ref()
    }
    /// <p>Sets the position of horizontal tiles.</p>
    pub fn tile_position(&self) -> ::std::option::Option<&crate::types::HorizontalTilePosition> {
        self.tile_position.as_ref()
    }
    /// <p>The maximum number of video tiles to display.</p>
    pub fn tile_count(&self) -> ::std::option::Option<i32> {
        self.tile_count
    }
    /// <p>Specifies the aspect ratio of all video tiles.</p>
    pub fn tile_aspect_ratio(&self) -> ::std::option::Option<&str> {
        self.tile_aspect_ratio.as_deref()
    }
}
impl HorizontalLayoutConfiguration {
    /// Creates a new builder-style object to manufacture [`HorizontalLayoutConfiguration`](crate::types::HorizontalLayoutConfiguration).
    pub fn builder() -> crate::types::builders::HorizontalLayoutConfigurationBuilder {
        crate::types::builders::HorizontalLayoutConfigurationBuilder::default()
    }
}

/// A builder for [`HorizontalLayoutConfiguration`](crate::types::HorizontalLayoutConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HorizontalLayoutConfigurationBuilder {
    pub(crate) tile_order: ::std::option::Option<crate::types::TileOrder>,
    pub(crate) tile_position: ::std::option::Option<crate::types::HorizontalTilePosition>,
    pub(crate) tile_count: ::std::option::Option<i32>,
    pub(crate) tile_aspect_ratio: ::std::option::Option<::std::string::String>,
}
impl HorizontalLayoutConfigurationBuilder {
    /// <p>Sets the automatic ordering of the video tiles.</p>
    pub fn tile_order(mut self, input: crate::types::TileOrder) -> Self {
        self.tile_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the automatic ordering of the video tiles.</p>
    pub fn set_tile_order(mut self, input: ::std::option::Option<crate::types::TileOrder>) -> Self {
        self.tile_order = input;
        self
    }
    /// <p>Sets the automatic ordering of the video tiles.</p>
    pub fn get_tile_order(&self) -> &::std::option::Option<crate::types::TileOrder> {
        &self.tile_order
    }
    /// <p>Sets the position of horizontal tiles.</p>
    pub fn tile_position(mut self, input: crate::types::HorizontalTilePosition) -> Self {
        self.tile_position = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the position of horizontal tiles.</p>
    pub fn set_tile_position(mut self, input: ::std::option::Option<crate::types::HorizontalTilePosition>) -> Self {
        self.tile_position = input;
        self
    }
    /// <p>Sets the position of horizontal tiles.</p>
    pub fn get_tile_position(&self) -> &::std::option::Option<crate::types::HorizontalTilePosition> {
        &self.tile_position
    }
    /// <p>The maximum number of video tiles to display.</p>
    pub fn tile_count(mut self, input: i32) -> Self {
        self.tile_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of video tiles to display.</p>
    pub fn set_tile_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.tile_count = input;
        self
    }
    /// <p>The maximum number of video tiles to display.</p>
    pub fn get_tile_count(&self) -> &::std::option::Option<i32> {
        &self.tile_count
    }
    /// <p>Specifies the aspect ratio of all video tiles.</p>
    pub fn tile_aspect_ratio(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tile_aspect_ratio = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the aspect ratio of all video tiles.</p>
    pub fn set_tile_aspect_ratio(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tile_aspect_ratio = input;
        self
    }
    /// <p>Specifies the aspect ratio of all video tiles.</p>
    pub fn get_tile_aspect_ratio(&self) -> &::std::option::Option<::std::string::String> {
        &self.tile_aspect_ratio
    }
    /// Consumes the builder and constructs a [`HorizontalLayoutConfiguration`](crate::types::HorizontalLayoutConfiguration).
    pub fn build(self) -> crate::types::HorizontalLayoutConfiguration {
        crate::types::HorizontalLayoutConfiguration {
            tile_order: self.tile_order,
            tile_position: self.tile_position,
            tile_count: self.tile_count,
            tile_aspect_ratio: self.tile_aspect_ratio,
        }
    }
}
