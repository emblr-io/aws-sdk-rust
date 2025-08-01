// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Details about the media file's video track.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoProperties {
    /// The bit depth of the video track.
    pub bit_depth: ::std::option::Option<i32>,
    /// The bit rate of the video track, in bits per second.
    pub bit_rate: ::std::option::Option<i64>,
    /// The color space color primaries of the video track.
    pub color_primaries: ::std::option::Option<crate::types::ColorPrimaries>,
    /// The frame rate of the video or audio track.
    pub frame_rate: ::std::option::Option<crate::types::FrameRate>,
    /// The height of the video track, in pixels.
    pub height: ::std::option::Option<i32>,
    /// The color space matrix coefficients of the video track.
    pub matrix_coefficients: ::std::option::Option<crate::types::MatrixCoefficients>,
    /// The color space transfer characteristics of the video track.
    pub transfer_characteristics: ::std::option::Option<crate::types::TransferCharacteristics>,
    /// The width of the video track, in pixels.
    pub width: ::std::option::Option<i32>,
}
impl VideoProperties {
    /// The bit depth of the video track.
    pub fn bit_depth(&self) -> ::std::option::Option<i32> {
        self.bit_depth
    }
    /// The bit rate of the video track, in bits per second.
    pub fn bit_rate(&self) -> ::std::option::Option<i64> {
        self.bit_rate
    }
    /// The color space color primaries of the video track.
    pub fn color_primaries(&self) -> ::std::option::Option<&crate::types::ColorPrimaries> {
        self.color_primaries.as_ref()
    }
    /// The frame rate of the video or audio track.
    pub fn frame_rate(&self) -> ::std::option::Option<&crate::types::FrameRate> {
        self.frame_rate.as_ref()
    }
    /// The height of the video track, in pixels.
    pub fn height(&self) -> ::std::option::Option<i32> {
        self.height
    }
    /// The color space matrix coefficients of the video track.
    pub fn matrix_coefficients(&self) -> ::std::option::Option<&crate::types::MatrixCoefficients> {
        self.matrix_coefficients.as_ref()
    }
    /// The color space transfer characteristics of the video track.
    pub fn transfer_characteristics(&self) -> ::std::option::Option<&crate::types::TransferCharacteristics> {
        self.transfer_characteristics.as_ref()
    }
    /// The width of the video track, in pixels.
    pub fn width(&self) -> ::std::option::Option<i32> {
        self.width
    }
}
impl VideoProperties {
    /// Creates a new builder-style object to manufacture [`VideoProperties`](crate::types::VideoProperties).
    pub fn builder() -> crate::types::builders::VideoPropertiesBuilder {
        crate::types::builders::VideoPropertiesBuilder::default()
    }
}

/// A builder for [`VideoProperties`](crate::types::VideoProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoPropertiesBuilder {
    pub(crate) bit_depth: ::std::option::Option<i32>,
    pub(crate) bit_rate: ::std::option::Option<i64>,
    pub(crate) color_primaries: ::std::option::Option<crate::types::ColorPrimaries>,
    pub(crate) frame_rate: ::std::option::Option<crate::types::FrameRate>,
    pub(crate) height: ::std::option::Option<i32>,
    pub(crate) matrix_coefficients: ::std::option::Option<crate::types::MatrixCoefficients>,
    pub(crate) transfer_characteristics: ::std::option::Option<crate::types::TransferCharacteristics>,
    pub(crate) width: ::std::option::Option<i32>,
}
impl VideoPropertiesBuilder {
    /// The bit depth of the video track.
    pub fn bit_depth(mut self, input: i32) -> Self {
        self.bit_depth = ::std::option::Option::Some(input);
        self
    }
    /// The bit depth of the video track.
    pub fn set_bit_depth(mut self, input: ::std::option::Option<i32>) -> Self {
        self.bit_depth = input;
        self
    }
    /// The bit depth of the video track.
    pub fn get_bit_depth(&self) -> &::std::option::Option<i32> {
        &self.bit_depth
    }
    /// The bit rate of the video track, in bits per second.
    pub fn bit_rate(mut self, input: i64) -> Self {
        self.bit_rate = ::std::option::Option::Some(input);
        self
    }
    /// The bit rate of the video track, in bits per second.
    pub fn set_bit_rate(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bit_rate = input;
        self
    }
    /// The bit rate of the video track, in bits per second.
    pub fn get_bit_rate(&self) -> &::std::option::Option<i64> {
        &self.bit_rate
    }
    /// The color space color primaries of the video track.
    pub fn color_primaries(mut self, input: crate::types::ColorPrimaries) -> Self {
        self.color_primaries = ::std::option::Option::Some(input);
        self
    }
    /// The color space color primaries of the video track.
    pub fn set_color_primaries(mut self, input: ::std::option::Option<crate::types::ColorPrimaries>) -> Self {
        self.color_primaries = input;
        self
    }
    /// The color space color primaries of the video track.
    pub fn get_color_primaries(&self) -> &::std::option::Option<crate::types::ColorPrimaries> {
        &self.color_primaries
    }
    /// The frame rate of the video or audio track.
    pub fn frame_rate(mut self, input: crate::types::FrameRate) -> Self {
        self.frame_rate = ::std::option::Option::Some(input);
        self
    }
    /// The frame rate of the video or audio track.
    pub fn set_frame_rate(mut self, input: ::std::option::Option<crate::types::FrameRate>) -> Self {
        self.frame_rate = input;
        self
    }
    /// The frame rate of the video or audio track.
    pub fn get_frame_rate(&self) -> &::std::option::Option<crate::types::FrameRate> {
        &self.frame_rate
    }
    /// The height of the video track, in pixels.
    pub fn height(mut self, input: i32) -> Self {
        self.height = ::std::option::Option::Some(input);
        self
    }
    /// The height of the video track, in pixels.
    pub fn set_height(mut self, input: ::std::option::Option<i32>) -> Self {
        self.height = input;
        self
    }
    /// The height of the video track, in pixels.
    pub fn get_height(&self) -> &::std::option::Option<i32> {
        &self.height
    }
    /// The color space matrix coefficients of the video track.
    pub fn matrix_coefficients(mut self, input: crate::types::MatrixCoefficients) -> Self {
        self.matrix_coefficients = ::std::option::Option::Some(input);
        self
    }
    /// The color space matrix coefficients of the video track.
    pub fn set_matrix_coefficients(mut self, input: ::std::option::Option<crate::types::MatrixCoefficients>) -> Self {
        self.matrix_coefficients = input;
        self
    }
    /// The color space matrix coefficients of the video track.
    pub fn get_matrix_coefficients(&self) -> &::std::option::Option<crate::types::MatrixCoefficients> {
        &self.matrix_coefficients
    }
    /// The color space transfer characteristics of the video track.
    pub fn transfer_characteristics(mut self, input: crate::types::TransferCharacteristics) -> Self {
        self.transfer_characteristics = ::std::option::Option::Some(input);
        self
    }
    /// The color space transfer characteristics of the video track.
    pub fn set_transfer_characteristics(mut self, input: ::std::option::Option<crate::types::TransferCharacteristics>) -> Self {
        self.transfer_characteristics = input;
        self
    }
    /// The color space transfer characteristics of the video track.
    pub fn get_transfer_characteristics(&self) -> &::std::option::Option<crate::types::TransferCharacteristics> {
        &self.transfer_characteristics
    }
    /// The width of the video track, in pixels.
    pub fn width(mut self, input: i32) -> Self {
        self.width = ::std::option::Option::Some(input);
        self
    }
    /// The width of the video track, in pixels.
    pub fn set_width(mut self, input: ::std::option::Option<i32>) -> Self {
        self.width = input;
        self
    }
    /// The width of the video track, in pixels.
    pub fn get_width(&self) -> &::std::option::Option<i32> {
        &self.width
    }
    /// Consumes the builder and constructs a [`VideoProperties`](crate::types::VideoProperties).
    pub fn build(self) -> crate::types::VideoProperties {
        crate::types::VideoProperties {
            bit_depth: self.bit_depth,
            bit_rate: self.bit_rate,
            color_primaries: self.color_primaries,
            frame_rate: self.frame_rate,
            height: self.height,
            matrix_coefficients: self.matrix_coefficients,
            transfer_characteristics: self.transfer_characteristics,
            width: self.width,
        }
    }
}
