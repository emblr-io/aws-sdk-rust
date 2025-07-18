// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Property of ColorCorrectionSettings. Used for custom color space conversion. The object identifies one 3D LUT file and specifies the input/output color space combination that the file will be used for.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ColorCorrection {
    /// The color space of the input.
    pub input_color_space: ::std::option::Option<crate::types::ColorSpace>,
    /// The color space of the output.
    pub output_color_space: ::std::option::Option<crate::types::ColorSpace>,
    /// The URI of the 3D LUT file. The protocol must be 's3:' or 's3ssl:':.
    pub uri: ::std::option::Option<::std::string::String>,
}
impl ColorCorrection {
    /// The color space of the input.
    pub fn input_color_space(&self) -> ::std::option::Option<&crate::types::ColorSpace> {
        self.input_color_space.as_ref()
    }
    /// The color space of the output.
    pub fn output_color_space(&self) -> ::std::option::Option<&crate::types::ColorSpace> {
        self.output_color_space.as_ref()
    }
    /// The URI of the 3D LUT file. The protocol must be 's3:' or 's3ssl:':.
    pub fn uri(&self) -> ::std::option::Option<&str> {
        self.uri.as_deref()
    }
}
impl ColorCorrection {
    /// Creates a new builder-style object to manufacture [`ColorCorrection`](crate::types::ColorCorrection).
    pub fn builder() -> crate::types::builders::ColorCorrectionBuilder {
        crate::types::builders::ColorCorrectionBuilder::default()
    }
}

/// A builder for [`ColorCorrection`](crate::types::ColorCorrection).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ColorCorrectionBuilder {
    pub(crate) input_color_space: ::std::option::Option<crate::types::ColorSpace>,
    pub(crate) output_color_space: ::std::option::Option<crate::types::ColorSpace>,
    pub(crate) uri: ::std::option::Option<::std::string::String>,
}
impl ColorCorrectionBuilder {
    /// The color space of the input.
    /// This field is required.
    pub fn input_color_space(mut self, input: crate::types::ColorSpace) -> Self {
        self.input_color_space = ::std::option::Option::Some(input);
        self
    }
    /// The color space of the input.
    pub fn set_input_color_space(mut self, input: ::std::option::Option<crate::types::ColorSpace>) -> Self {
        self.input_color_space = input;
        self
    }
    /// The color space of the input.
    pub fn get_input_color_space(&self) -> &::std::option::Option<crate::types::ColorSpace> {
        &self.input_color_space
    }
    /// The color space of the output.
    /// This field is required.
    pub fn output_color_space(mut self, input: crate::types::ColorSpace) -> Self {
        self.output_color_space = ::std::option::Option::Some(input);
        self
    }
    /// The color space of the output.
    pub fn set_output_color_space(mut self, input: ::std::option::Option<crate::types::ColorSpace>) -> Self {
        self.output_color_space = input;
        self
    }
    /// The color space of the output.
    pub fn get_output_color_space(&self) -> &::std::option::Option<crate::types::ColorSpace> {
        &self.output_color_space
    }
    /// The URI of the 3D LUT file. The protocol must be 's3:' or 's3ssl:':.
    /// This field is required.
    pub fn uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.uri = ::std::option::Option::Some(input.into());
        self
    }
    /// The URI of the 3D LUT file. The protocol must be 's3:' or 's3ssl:':.
    pub fn set_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.uri = input;
        self
    }
    /// The URI of the 3D LUT file. The protocol must be 's3:' or 's3ssl:':.
    pub fn get_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.uri
    }
    /// Consumes the builder and constructs a [`ColorCorrection`](crate::types::ColorCorrection).
    pub fn build(self) -> crate::types::ColorCorrection {
        crate::types::ColorCorrection {
            input_color_space: self.input_color_space,
            output_color_space: self.output_color_space,
            uri: self.uri,
        }
    }
}
