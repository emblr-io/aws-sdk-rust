// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// To transcode only portions of your video overlay, include one input clip for each part of your video overlay that you want in your output.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoOverlayInputClipping {
    /// Specify the timecode of the last frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub end_timecode: ::std::option::Option<::std::string::String>,
    /// Specify the timecode of the first frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub start_timecode: ::std::option::Option<::std::string::String>,
}
impl VideoOverlayInputClipping {
    /// Specify the timecode of the last frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn end_timecode(&self) -> ::std::option::Option<&str> {
        self.end_timecode.as_deref()
    }
    /// Specify the timecode of the first frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn start_timecode(&self) -> ::std::option::Option<&str> {
        self.start_timecode.as_deref()
    }
}
impl VideoOverlayInputClipping {
    /// Creates a new builder-style object to manufacture [`VideoOverlayInputClipping`](crate::types::VideoOverlayInputClipping).
    pub fn builder() -> crate::types::builders::VideoOverlayInputClippingBuilder {
        crate::types::builders::VideoOverlayInputClippingBuilder::default()
    }
}

/// A builder for [`VideoOverlayInputClipping`](crate::types::VideoOverlayInputClipping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoOverlayInputClippingBuilder {
    pub(crate) end_timecode: ::std::option::Option<::std::string::String>,
    pub(crate) start_timecode: ::std::option::Option<::std::string::String>,
}
impl VideoOverlayInputClippingBuilder {
    /// Specify the timecode of the last frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn end_timecode(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_timecode = ::std::option::Option::Some(input.into());
        self
    }
    /// Specify the timecode of the last frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn set_end_timecode(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_timecode = input;
        self
    }
    /// Specify the timecode of the last frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn get_end_timecode(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_timecode
    }
    /// Specify the timecode of the first frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn start_timecode(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_timecode = ::std::option::Option::Some(input.into());
        self
    }
    /// Specify the timecode of the first frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn set_start_timecode(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_timecode = input;
        self
    }
    /// Specify the timecode of the first frame to include in your video overlay's clip. Use the format HH:MM:SS:FF or HH:MM:SS;FF, where HH is the hour, MM is the minute, SS is the second, and FF is the frame number. When entering this value, take into account your choice for Timecode source.
    pub fn get_start_timecode(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_timecode
    }
    /// Consumes the builder and constructs a [`VideoOverlayInputClipping`](crate::types::VideoOverlayInputClipping).
    pub fn build(self) -> crate::types::VideoOverlayInputClipping {
        crate::types::VideoOverlayInputClipping {
            end_timecode: self.end_timecode,
            start_timecode: self.start_timecode,
        }
    }
}
