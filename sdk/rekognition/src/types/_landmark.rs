// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates the location of the landmark on the face.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Landmark {
    /// <p>Type of landmark.</p>
    pub r#type: ::std::option::Option<crate::types::LandmarkType>,
    /// <p>The x-coordinate of the landmark expressed as a ratio of the width of the image. The x-coordinate is measured from the left-side of the image. For example, if the image is 700 pixels wide and the x-coordinate of the landmark is at 350 pixels, this value is 0.5.</p>
    pub x: ::std::option::Option<f32>,
    /// <p>The y-coordinate of the landmark expressed as a ratio of the height of the image. The y-coordinate is measured from the top of the image. For example, if the image height is 200 pixels and the y-coordinate of the landmark is at 50 pixels, this value is 0.25.</p>
    pub y: ::std::option::Option<f32>,
}
impl Landmark {
    /// <p>Type of landmark.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::LandmarkType> {
        self.r#type.as_ref()
    }
    /// <p>The x-coordinate of the landmark expressed as a ratio of the width of the image. The x-coordinate is measured from the left-side of the image. For example, if the image is 700 pixels wide and the x-coordinate of the landmark is at 350 pixels, this value is 0.5.</p>
    pub fn x(&self) -> ::std::option::Option<f32> {
        self.x
    }
    /// <p>The y-coordinate of the landmark expressed as a ratio of the height of the image. The y-coordinate is measured from the top of the image. For example, if the image height is 200 pixels and the y-coordinate of the landmark is at 50 pixels, this value is 0.25.</p>
    pub fn y(&self) -> ::std::option::Option<f32> {
        self.y
    }
}
impl Landmark {
    /// Creates a new builder-style object to manufacture [`Landmark`](crate::types::Landmark).
    pub fn builder() -> crate::types::builders::LandmarkBuilder {
        crate::types::builders::LandmarkBuilder::default()
    }
}

/// A builder for [`Landmark`](crate::types::Landmark).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LandmarkBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::LandmarkType>,
    pub(crate) x: ::std::option::Option<f32>,
    pub(crate) y: ::std::option::Option<f32>,
}
impl LandmarkBuilder {
    /// <p>Type of landmark.</p>
    pub fn r#type(mut self, input: crate::types::LandmarkType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of landmark.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::LandmarkType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of landmark.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::LandmarkType> {
        &self.r#type
    }
    /// <p>The x-coordinate of the landmark expressed as a ratio of the width of the image. The x-coordinate is measured from the left-side of the image. For example, if the image is 700 pixels wide and the x-coordinate of the landmark is at 350 pixels, this value is 0.5.</p>
    pub fn x(mut self, input: f32) -> Self {
        self.x = ::std::option::Option::Some(input);
        self
    }
    /// <p>The x-coordinate of the landmark expressed as a ratio of the width of the image. The x-coordinate is measured from the left-side of the image. For example, if the image is 700 pixels wide and the x-coordinate of the landmark is at 350 pixels, this value is 0.5.</p>
    pub fn set_x(mut self, input: ::std::option::Option<f32>) -> Self {
        self.x = input;
        self
    }
    /// <p>The x-coordinate of the landmark expressed as a ratio of the width of the image. The x-coordinate is measured from the left-side of the image. For example, if the image is 700 pixels wide and the x-coordinate of the landmark is at 350 pixels, this value is 0.5.</p>
    pub fn get_x(&self) -> &::std::option::Option<f32> {
        &self.x
    }
    /// <p>The y-coordinate of the landmark expressed as a ratio of the height of the image. The y-coordinate is measured from the top of the image. For example, if the image height is 200 pixels and the y-coordinate of the landmark is at 50 pixels, this value is 0.25.</p>
    pub fn y(mut self, input: f32) -> Self {
        self.y = ::std::option::Option::Some(input);
        self
    }
    /// <p>The y-coordinate of the landmark expressed as a ratio of the height of the image. The y-coordinate is measured from the top of the image. For example, if the image height is 200 pixels and the y-coordinate of the landmark is at 50 pixels, this value is 0.25.</p>
    pub fn set_y(mut self, input: ::std::option::Option<f32>) -> Self {
        self.y = input;
        self
    }
    /// <p>The y-coordinate of the landmark expressed as a ratio of the height of the image. The y-coordinate is measured from the top of the image. For example, if the image height is 200 pixels and the y-coordinate of the landmark is at 50 pixels, this value is 0.25.</p>
    pub fn get_y(&self) -> &::std::option::Option<f32> {
        &self.y
    }
    /// Consumes the builder and constructs a [`Landmark`](crate::types::Landmark).
    pub fn build(self) -> crate::types::Landmark {
        crate::types::Landmark {
            r#type: self.r#type,
            x: self.x,
            y: self.y,
        }
    }
}
