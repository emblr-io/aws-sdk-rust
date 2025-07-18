// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The bounding box around the detected page, text, key-value pair, table, table cell, or selection element on a document page. The <code>left</code> (x-coordinate) and <code>top</code> (y-coordinate) are coordinates that represent the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
/// <p>The <code>top</code> and <code>left</code> values returned are ratios of the overall document page size. For example, if the input image is 700 x 200 pixels, and the top-left coordinate of the bounding box is 350 x 50 pixels, the API returns a <code>left</code> value of 0.5 (350/700) and a <code>top</code> value of 0.25 (50/200).</p>
/// <p>The <code>width</code> and <code>height</code> values represent the dimensions of the bounding box as a ratio of the overall document page dimension. For example, if the document page size is 700 x 200 pixels, and the bounding box width is 70 pixels, the width returned is 0.1.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BoundingBox {
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub width: f32,
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub height: f32,
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub left: f32,
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub top: f32,
}
impl BoundingBox {
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub fn width(&self) -> f32 {
        self.width
    }
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub fn height(&self) -> f32 {
        self.height
    }
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub fn left(&self) -> f32 {
        self.left
    }
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub fn top(&self) -> f32 {
        self.top
    }
}
impl BoundingBox {
    /// Creates a new builder-style object to manufacture [`BoundingBox`](crate::types::BoundingBox).
    pub fn builder() -> crate::types::builders::BoundingBoxBuilder {
        crate::types::builders::BoundingBoxBuilder::default()
    }
}

/// A builder for [`BoundingBox`](crate::types::BoundingBox).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BoundingBoxBuilder {
    pub(crate) width: ::std::option::Option<f32>,
    pub(crate) height: ::std::option::Option<f32>,
    pub(crate) left: ::std::option::Option<f32>,
    pub(crate) top: ::std::option::Option<f32>,
}
impl BoundingBoxBuilder {
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub fn width(mut self, input: f32) -> Self {
        self.width = ::std::option::Option::Some(input);
        self
    }
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub fn set_width(mut self, input: ::std::option::Option<f32>) -> Self {
        self.width = input;
        self
    }
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub fn get_width(&self) -> &::std::option::Option<f32> {
        &self.width
    }
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub fn height(mut self, input: f32) -> Self {
        self.height = ::std::option::Option::Some(input);
        self
    }
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub fn set_height(mut self, input: ::std::option::Option<f32>) -> Self {
        self.height = input;
        self
    }
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub fn get_height(&self) -> &::std::option::Option<f32> {
        &self.height
    }
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub fn left(mut self, input: f32) -> Self {
        self.left = ::std::option::Option::Some(input);
        self
    }
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub fn set_left(mut self, input: ::std::option::Option<f32>) -> Self {
        self.left = input;
        self
    }
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub fn get_left(&self) -> &::std::option::Option<f32> {
        &self.left
    }
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub fn top(mut self, input: f32) -> Self {
        self.top = ::std::option::Option::Some(input);
        self
    }
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub fn set_top(mut self, input: ::std::option::Option<f32>) -> Self {
        self.top = input;
        self
    }
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub fn get_top(&self) -> &::std::option::Option<f32> {
        &self.top
    }
    /// Consumes the builder and constructs a [`BoundingBox`](crate::types::BoundingBox).
    pub fn build(self) -> crate::types::BoundingBox {
        crate::types::BoundingBox {
            width: self.width.unwrap_or_default(),
            height: self.height.unwrap_or_default(),
            left: self.left.unwrap_or_default(),
            top: self.top.unwrap_or_default(),
        }
    }
}
