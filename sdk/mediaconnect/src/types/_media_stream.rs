// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A media stream represents one component of your content, such as video, audio, or ancillary data. After you add a media stream to your flow, you can associate it with sources and outputs that use the ST 2110 JPEG XS or CDI protocol.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaStream {
    /// <p>Attributes that are related to the media stream.</p>
    pub attributes: ::std::option::Option<crate::types::MediaStreamAttributes>,
    /// <p>The sample rate for the stream. This value is measured in Hz.</p>
    pub clock_rate: ::std::option::Option<i32>,
    /// <p>A description that can help you quickly identify what your media stream is used for.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The format type number (sometimes referred to as RTP payload type) of the media stream. MediaConnect assigns this value to the media stream. For ST 2110 JPEG XS outputs, you need to provide this value to the receiver.</p>
    pub fmt: ::std::option::Option<i32>,
    /// <p>A unique identifier for the media stream.</p>
    pub media_stream_id: ::std::option::Option<i32>,
    /// <p>A name that helps you distinguish one media stream from another.</p>
    pub media_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of media stream.</p>
    pub media_stream_type: ::std::option::Option<crate::types::MediaStreamType>,
    /// <p>The resolution of the video.</p>
    pub video_format: ::std::option::Option<::std::string::String>,
}
impl MediaStream {
    /// <p>Attributes that are related to the media stream.</p>
    pub fn attributes(&self) -> ::std::option::Option<&crate::types::MediaStreamAttributes> {
        self.attributes.as_ref()
    }
    /// <p>The sample rate for the stream. This value is measured in Hz.</p>
    pub fn clock_rate(&self) -> ::std::option::Option<i32> {
        self.clock_rate
    }
    /// <p>A description that can help you quickly identify what your media stream is used for.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The format type number (sometimes referred to as RTP payload type) of the media stream. MediaConnect assigns this value to the media stream. For ST 2110 JPEG XS outputs, you need to provide this value to the receiver.</p>
    pub fn fmt(&self) -> ::std::option::Option<i32> {
        self.fmt
    }
    /// <p>A unique identifier for the media stream.</p>
    pub fn media_stream_id(&self) -> ::std::option::Option<i32> {
        self.media_stream_id
    }
    /// <p>A name that helps you distinguish one media stream from another.</p>
    pub fn media_stream_name(&self) -> ::std::option::Option<&str> {
        self.media_stream_name.as_deref()
    }
    /// <p>The type of media stream.</p>
    pub fn media_stream_type(&self) -> ::std::option::Option<&crate::types::MediaStreamType> {
        self.media_stream_type.as_ref()
    }
    /// <p>The resolution of the video.</p>
    pub fn video_format(&self) -> ::std::option::Option<&str> {
        self.video_format.as_deref()
    }
}
impl MediaStream {
    /// Creates a new builder-style object to manufacture [`MediaStream`](crate::types::MediaStream).
    pub fn builder() -> crate::types::builders::MediaStreamBuilder {
        crate::types::builders::MediaStreamBuilder::default()
    }
}

/// A builder for [`MediaStream`](crate::types::MediaStream).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaStreamBuilder {
    pub(crate) attributes: ::std::option::Option<crate::types::MediaStreamAttributes>,
    pub(crate) clock_rate: ::std::option::Option<i32>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) fmt: ::std::option::Option<i32>,
    pub(crate) media_stream_id: ::std::option::Option<i32>,
    pub(crate) media_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) media_stream_type: ::std::option::Option<crate::types::MediaStreamType>,
    pub(crate) video_format: ::std::option::Option<::std::string::String>,
}
impl MediaStreamBuilder {
    /// <p>Attributes that are related to the media stream.</p>
    pub fn attributes(mut self, input: crate::types::MediaStreamAttributes) -> Self {
        self.attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Attributes that are related to the media stream.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<crate::types::MediaStreamAttributes>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Attributes that are related to the media stream.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<crate::types::MediaStreamAttributes> {
        &self.attributes
    }
    /// <p>The sample rate for the stream. This value is measured in Hz.</p>
    pub fn clock_rate(mut self, input: i32) -> Self {
        self.clock_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sample rate for the stream. This value is measured in Hz.</p>
    pub fn set_clock_rate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.clock_rate = input;
        self
    }
    /// <p>The sample rate for the stream. This value is measured in Hz.</p>
    pub fn get_clock_rate(&self) -> &::std::option::Option<i32> {
        &self.clock_rate
    }
    /// <p>A description that can help you quickly identify what your media stream is used for.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description that can help you quickly identify what your media stream is used for.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description that can help you quickly identify what your media stream is used for.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The format type number (sometimes referred to as RTP payload type) of the media stream. MediaConnect assigns this value to the media stream. For ST 2110 JPEG XS outputs, you need to provide this value to the receiver.</p>
    /// This field is required.
    pub fn fmt(mut self, input: i32) -> Self {
        self.fmt = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format type number (sometimes referred to as RTP payload type) of the media stream. MediaConnect assigns this value to the media stream. For ST 2110 JPEG XS outputs, you need to provide this value to the receiver.</p>
    pub fn set_fmt(mut self, input: ::std::option::Option<i32>) -> Self {
        self.fmt = input;
        self
    }
    /// <p>The format type number (sometimes referred to as RTP payload type) of the media stream. MediaConnect assigns this value to the media stream. For ST 2110 JPEG XS outputs, you need to provide this value to the receiver.</p>
    pub fn get_fmt(&self) -> &::std::option::Option<i32> {
        &self.fmt
    }
    /// <p>A unique identifier for the media stream.</p>
    /// This field is required.
    pub fn media_stream_id(mut self, input: i32) -> Self {
        self.media_stream_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>A unique identifier for the media stream.</p>
    pub fn set_media_stream_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.media_stream_id = input;
        self
    }
    /// <p>A unique identifier for the media stream.</p>
    pub fn get_media_stream_id(&self) -> &::std::option::Option<i32> {
        &self.media_stream_id
    }
    /// <p>A name that helps you distinguish one media stream from another.</p>
    /// This field is required.
    pub fn media_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.media_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name that helps you distinguish one media stream from another.</p>
    pub fn set_media_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.media_stream_name = input;
        self
    }
    /// <p>A name that helps you distinguish one media stream from another.</p>
    pub fn get_media_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.media_stream_name
    }
    /// <p>The type of media stream.</p>
    /// This field is required.
    pub fn media_stream_type(mut self, input: crate::types::MediaStreamType) -> Self {
        self.media_stream_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of media stream.</p>
    pub fn set_media_stream_type(mut self, input: ::std::option::Option<crate::types::MediaStreamType>) -> Self {
        self.media_stream_type = input;
        self
    }
    /// <p>The type of media stream.</p>
    pub fn get_media_stream_type(&self) -> &::std::option::Option<crate::types::MediaStreamType> {
        &self.media_stream_type
    }
    /// <p>The resolution of the video.</p>
    pub fn video_format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.video_format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resolution of the video.</p>
    pub fn set_video_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.video_format = input;
        self
    }
    /// <p>The resolution of the video.</p>
    pub fn get_video_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.video_format
    }
    /// Consumes the builder and constructs a [`MediaStream`](crate::types::MediaStream).
    pub fn build(self) -> crate::types::MediaStream {
        crate::types::MediaStream {
            attributes: self.attributes,
            clock_rate: self.clock_rate,
            description: self.description,
            fmt: self.fmt,
            media_stream_id: self.media_stream_id,
            media_stream_name: self.media_stream_name,
            media_stream_type: self.media_stream_type,
            video_format: self.video_format,
        }
    }
}
