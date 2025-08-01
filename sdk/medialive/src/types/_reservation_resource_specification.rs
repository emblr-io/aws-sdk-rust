// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Resource configuration (codec, resolution, bitrate, ...)
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReservationResourceSpecification {
    /// Channel class, e.g. 'STANDARD'
    pub channel_class: ::std::option::Option<crate::types::ChannelClass>,
    /// Codec, e.g. 'AVC'
    pub codec: ::std::option::Option<crate::types::ReservationCodec>,
    /// Maximum bitrate, e.g. 'MAX_20_MBPS'
    pub maximum_bitrate: ::std::option::Option<crate::types::ReservationMaximumBitrate>,
    /// Maximum framerate, e.g. 'MAX_30_FPS' (Outputs only)
    pub maximum_framerate: ::std::option::Option<crate::types::ReservationMaximumFramerate>,
    /// Resolution, e.g. 'HD'
    pub resolution: ::std::option::Option<crate::types::ReservationResolution>,
    /// Resource type, 'INPUT', 'OUTPUT', 'MULTIPLEX', or 'CHANNEL'
    pub resource_type: ::std::option::Option<crate::types::ReservationResourceType>,
    /// Special feature, e.g. 'AUDIO_NORMALIZATION' (Channels only)
    pub special_feature: ::std::option::Option<crate::types::ReservationSpecialFeature>,
    /// Video quality, e.g. 'STANDARD' (Outputs only)
    pub video_quality: ::std::option::Option<crate::types::ReservationVideoQuality>,
}
impl ReservationResourceSpecification {
    /// Channel class, e.g. 'STANDARD'
    pub fn channel_class(&self) -> ::std::option::Option<&crate::types::ChannelClass> {
        self.channel_class.as_ref()
    }
    /// Codec, e.g. 'AVC'
    pub fn codec(&self) -> ::std::option::Option<&crate::types::ReservationCodec> {
        self.codec.as_ref()
    }
    /// Maximum bitrate, e.g. 'MAX_20_MBPS'
    pub fn maximum_bitrate(&self) -> ::std::option::Option<&crate::types::ReservationMaximumBitrate> {
        self.maximum_bitrate.as_ref()
    }
    /// Maximum framerate, e.g. 'MAX_30_FPS' (Outputs only)
    pub fn maximum_framerate(&self) -> ::std::option::Option<&crate::types::ReservationMaximumFramerate> {
        self.maximum_framerate.as_ref()
    }
    /// Resolution, e.g. 'HD'
    pub fn resolution(&self) -> ::std::option::Option<&crate::types::ReservationResolution> {
        self.resolution.as_ref()
    }
    /// Resource type, 'INPUT', 'OUTPUT', 'MULTIPLEX', or 'CHANNEL'
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ReservationResourceType> {
        self.resource_type.as_ref()
    }
    /// Special feature, e.g. 'AUDIO_NORMALIZATION' (Channels only)
    pub fn special_feature(&self) -> ::std::option::Option<&crate::types::ReservationSpecialFeature> {
        self.special_feature.as_ref()
    }
    /// Video quality, e.g. 'STANDARD' (Outputs only)
    pub fn video_quality(&self) -> ::std::option::Option<&crate::types::ReservationVideoQuality> {
        self.video_quality.as_ref()
    }
}
impl ReservationResourceSpecification {
    /// Creates a new builder-style object to manufacture [`ReservationResourceSpecification`](crate::types::ReservationResourceSpecification).
    pub fn builder() -> crate::types::builders::ReservationResourceSpecificationBuilder {
        crate::types::builders::ReservationResourceSpecificationBuilder::default()
    }
}

/// A builder for [`ReservationResourceSpecification`](crate::types::ReservationResourceSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReservationResourceSpecificationBuilder {
    pub(crate) channel_class: ::std::option::Option<crate::types::ChannelClass>,
    pub(crate) codec: ::std::option::Option<crate::types::ReservationCodec>,
    pub(crate) maximum_bitrate: ::std::option::Option<crate::types::ReservationMaximumBitrate>,
    pub(crate) maximum_framerate: ::std::option::Option<crate::types::ReservationMaximumFramerate>,
    pub(crate) resolution: ::std::option::Option<crate::types::ReservationResolution>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ReservationResourceType>,
    pub(crate) special_feature: ::std::option::Option<crate::types::ReservationSpecialFeature>,
    pub(crate) video_quality: ::std::option::Option<crate::types::ReservationVideoQuality>,
}
impl ReservationResourceSpecificationBuilder {
    /// Channel class, e.g. 'STANDARD'
    pub fn channel_class(mut self, input: crate::types::ChannelClass) -> Self {
        self.channel_class = ::std::option::Option::Some(input);
        self
    }
    /// Channel class, e.g. 'STANDARD'
    pub fn set_channel_class(mut self, input: ::std::option::Option<crate::types::ChannelClass>) -> Self {
        self.channel_class = input;
        self
    }
    /// Channel class, e.g. 'STANDARD'
    pub fn get_channel_class(&self) -> &::std::option::Option<crate::types::ChannelClass> {
        &self.channel_class
    }
    /// Codec, e.g. 'AVC'
    pub fn codec(mut self, input: crate::types::ReservationCodec) -> Self {
        self.codec = ::std::option::Option::Some(input);
        self
    }
    /// Codec, e.g. 'AVC'
    pub fn set_codec(mut self, input: ::std::option::Option<crate::types::ReservationCodec>) -> Self {
        self.codec = input;
        self
    }
    /// Codec, e.g. 'AVC'
    pub fn get_codec(&self) -> &::std::option::Option<crate::types::ReservationCodec> {
        &self.codec
    }
    /// Maximum bitrate, e.g. 'MAX_20_MBPS'
    pub fn maximum_bitrate(mut self, input: crate::types::ReservationMaximumBitrate) -> Self {
        self.maximum_bitrate = ::std::option::Option::Some(input);
        self
    }
    /// Maximum bitrate, e.g. 'MAX_20_MBPS'
    pub fn set_maximum_bitrate(mut self, input: ::std::option::Option<crate::types::ReservationMaximumBitrate>) -> Self {
        self.maximum_bitrate = input;
        self
    }
    /// Maximum bitrate, e.g. 'MAX_20_MBPS'
    pub fn get_maximum_bitrate(&self) -> &::std::option::Option<crate::types::ReservationMaximumBitrate> {
        &self.maximum_bitrate
    }
    /// Maximum framerate, e.g. 'MAX_30_FPS' (Outputs only)
    pub fn maximum_framerate(mut self, input: crate::types::ReservationMaximumFramerate) -> Self {
        self.maximum_framerate = ::std::option::Option::Some(input);
        self
    }
    /// Maximum framerate, e.g. 'MAX_30_FPS' (Outputs only)
    pub fn set_maximum_framerate(mut self, input: ::std::option::Option<crate::types::ReservationMaximumFramerate>) -> Self {
        self.maximum_framerate = input;
        self
    }
    /// Maximum framerate, e.g. 'MAX_30_FPS' (Outputs only)
    pub fn get_maximum_framerate(&self) -> &::std::option::Option<crate::types::ReservationMaximumFramerate> {
        &self.maximum_framerate
    }
    /// Resolution, e.g. 'HD'
    pub fn resolution(mut self, input: crate::types::ReservationResolution) -> Self {
        self.resolution = ::std::option::Option::Some(input);
        self
    }
    /// Resolution, e.g. 'HD'
    pub fn set_resolution(mut self, input: ::std::option::Option<crate::types::ReservationResolution>) -> Self {
        self.resolution = input;
        self
    }
    /// Resolution, e.g. 'HD'
    pub fn get_resolution(&self) -> &::std::option::Option<crate::types::ReservationResolution> {
        &self.resolution
    }
    /// Resource type, 'INPUT', 'OUTPUT', 'MULTIPLEX', or 'CHANNEL'
    pub fn resource_type(mut self, input: crate::types::ReservationResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// Resource type, 'INPUT', 'OUTPUT', 'MULTIPLEX', or 'CHANNEL'
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ReservationResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// Resource type, 'INPUT', 'OUTPUT', 'MULTIPLEX', or 'CHANNEL'
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ReservationResourceType> {
        &self.resource_type
    }
    /// Special feature, e.g. 'AUDIO_NORMALIZATION' (Channels only)
    pub fn special_feature(mut self, input: crate::types::ReservationSpecialFeature) -> Self {
        self.special_feature = ::std::option::Option::Some(input);
        self
    }
    /// Special feature, e.g. 'AUDIO_NORMALIZATION' (Channels only)
    pub fn set_special_feature(mut self, input: ::std::option::Option<crate::types::ReservationSpecialFeature>) -> Self {
        self.special_feature = input;
        self
    }
    /// Special feature, e.g. 'AUDIO_NORMALIZATION' (Channels only)
    pub fn get_special_feature(&self) -> &::std::option::Option<crate::types::ReservationSpecialFeature> {
        &self.special_feature
    }
    /// Video quality, e.g. 'STANDARD' (Outputs only)
    pub fn video_quality(mut self, input: crate::types::ReservationVideoQuality) -> Self {
        self.video_quality = ::std::option::Option::Some(input);
        self
    }
    /// Video quality, e.g. 'STANDARD' (Outputs only)
    pub fn set_video_quality(mut self, input: ::std::option::Option<crate::types::ReservationVideoQuality>) -> Self {
        self.video_quality = input;
        self
    }
    /// Video quality, e.g. 'STANDARD' (Outputs only)
    pub fn get_video_quality(&self) -> &::std::option::Option<crate::types::ReservationVideoQuality> {
        &self.video_quality
    }
    /// Consumes the builder and constructs a [`ReservationResourceSpecification`](crate::types::ReservationResourceSpecification).
    pub fn build(self) -> crate::types::ReservationResourceSpecification {
        crate::types::ReservationResourceSpecification {
            channel_class: self.channel_class,
            codec: self.codec,
            maximum_bitrate: self.maximum_bitrate,
            maximum_framerate: self.maximum_framerate,
            resolution: self.resolution,
            resource_type: self.resource_type,
            special_feature: self.special_feature,
            video_quality: self.video_quality,
        }
    }
}
