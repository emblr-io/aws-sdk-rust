// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for InputSpecification
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputSpecification {
    /// Input codec
    pub codec: ::std::option::Option<crate::types::InputCodec>,
    /// Maximum input bitrate, categorized coarsely
    pub maximum_bitrate: ::std::option::Option<crate::types::InputMaximumBitrate>,
    /// Input resolution, categorized coarsely
    pub resolution: ::std::option::Option<crate::types::InputResolution>,
}
impl InputSpecification {
    /// Input codec
    pub fn codec(&self) -> ::std::option::Option<&crate::types::InputCodec> {
        self.codec.as_ref()
    }
    /// Maximum input bitrate, categorized coarsely
    pub fn maximum_bitrate(&self) -> ::std::option::Option<&crate::types::InputMaximumBitrate> {
        self.maximum_bitrate.as_ref()
    }
    /// Input resolution, categorized coarsely
    pub fn resolution(&self) -> ::std::option::Option<&crate::types::InputResolution> {
        self.resolution.as_ref()
    }
}
impl InputSpecification {
    /// Creates a new builder-style object to manufacture [`InputSpecification`](crate::types::InputSpecification).
    pub fn builder() -> crate::types::builders::InputSpecificationBuilder {
        crate::types::builders::InputSpecificationBuilder::default()
    }
}

/// A builder for [`InputSpecification`](crate::types::InputSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputSpecificationBuilder {
    pub(crate) codec: ::std::option::Option<crate::types::InputCodec>,
    pub(crate) maximum_bitrate: ::std::option::Option<crate::types::InputMaximumBitrate>,
    pub(crate) resolution: ::std::option::Option<crate::types::InputResolution>,
}
impl InputSpecificationBuilder {
    /// Input codec
    pub fn codec(mut self, input: crate::types::InputCodec) -> Self {
        self.codec = ::std::option::Option::Some(input);
        self
    }
    /// Input codec
    pub fn set_codec(mut self, input: ::std::option::Option<crate::types::InputCodec>) -> Self {
        self.codec = input;
        self
    }
    /// Input codec
    pub fn get_codec(&self) -> &::std::option::Option<crate::types::InputCodec> {
        &self.codec
    }
    /// Maximum input bitrate, categorized coarsely
    pub fn maximum_bitrate(mut self, input: crate::types::InputMaximumBitrate) -> Self {
        self.maximum_bitrate = ::std::option::Option::Some(input);
        self
    }
    /// Maximum input bitrate, categorized coarsely
    pub fn set_maximum_bitrate(mut self, input: ::std::option::Option<crate::types::InputMaximumBitrate>) -> Self {
        self.maximum_bitrate = input;
        self
    }
    /// Maximum input bitrate, categorized coarsely
    pub fn get_maximum_bitrate(&self) -> &::std::option::Option<crate::types::InputMaximumBitrate> {
        &self.maximum_bitrate
    }
    /// Input resolution, categorized coarsely
    pub fn resolution(mut self, input: crate::types::InputResolution) -> Self {
        self.resolution = ::std::option::Option::Some(input);
        self
    }
    /// Input resolution, categorized coarsely
    pub fn set_resolution(mut self, input: ::std::option::Option<crate::types::InputResolution>) -> Self {
        self.resolution = input;
        self
    }
    /// Input resolution, categorized coarsely
    pub fn get_resolution(&self) -> &::std::option::Option<crate::types::InputResolution> {
        &self.resolution
    }
    /// Consumes the builder and constructs a [`InputSpecification`](crate::types::InputSpecification).
    pub fn build(self) -> crate::types::InputSpecification {
        crate::types::InputSpecification {
            codec: self.codec,
            maximum_bitrate: self.maximum_bitrate,
            resolution: self.resolution,
        }
    }
}
