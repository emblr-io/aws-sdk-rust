// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The bounding box around the detected page or around an element on a document page. The left (x-coordinate) and top (y-coordinate) are coordinates that represent the top and left sides of the bounding box. Note that the upper-left corner of the image is the origin (0,0).</p>
/// <p>For additional information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/API_BoundingBox.html">BoundingBox</a> in the Amazon Textract API reference.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BoundingBox {
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub height: ::std::option::Option<f32>,
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub left: ::std::option::Option<f32>,
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub top: ::std::option::Option<f32>,
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub width: ::std::option::Option<f32>,
}
impl BoundingBox {
    /// <p>The height of the bounding box as a ratio of the overall document page height.</p>
    pub fn height(&self) -> ::std::option::Option<f32> {
        self.height
    }
    /// <p>The left coordinate of the bounding box as a ratio of overall document page width.</p>
    pub fn left(&self) -> ::std::option::Option<f32> {
        self.left
    }
    /// <p>The top coordinate of the bounding box as a ratio of overall document page height.</p>
    pub fn top(&self) -> ::std::option::Option<f32> {
        self.top
    }
    /// <p>The width of the bounding box as a ratio of the overall document page width.</p>
    pub fn width(&self) -> ::std::option::Option<f32> {
        self.width
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
    pub(crate) height: ::std::option::Option<f32>,
    pub(crate) left: ::std::option::Option<f32>,
    pub(crate) top: ::std::option::Option<f32>,
    pub(crate) width: ::std::option::Option<f32>,
}
impl BoundingBoxBuilder {
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
    /// Consumes the builder and constructs a [`BoundingBox`](crate::types::BoundingBox).
    pub fn build(self) -> crate::types::BoundingBox {
        crate::types::BoundingBox {
            height: self.height,
            left: self.left,
            top: self.top,
            width: self.width,
        }
    }
}
