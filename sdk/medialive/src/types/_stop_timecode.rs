// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings to identify the end of the clip.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopTimecode {
    /// If you specify a StopTimecode in an input (in order to clip the file), you can specify if you want the clip to exclude (the default) or include the frame specified by the timecode.
    pub last_frame_clipping_behavior: ::std::option::Option<crate::types::LastFrameClippingBehavior>,
    /// The timecode for the frame where you want to stop the clip. Optional; if not specified, the clip continues to the end of the file. Enter the timecode as HH:MM:SS:FF or HH:MM:SS;FF.
    pub timecode: ::std::option::Option<::std::string::String>,
}
impl StopTimecode {
    /// If you specify a StopTimecode in an input (in order to clip the file), you can specify if you want the clip to exclude (the default) or include the frame specified by the timecode.
    pub fn last_frame_clipping_behavior(&self) -> ::std::option::Option<&crate::types::LastFrameClippingBehavior> {
        self.last_frame_clipping_behavior.as_ref()
    }
    /// The timecode for the frame where you want to stop the clip. Optional; if not specified, the clip continues to the end of the file. Enter the timecode as HH:MM:SS:FF or HH:MM:SS;FF.
    pub fn timecode(&self) -> ::std::option::Option<&str> {
        self.timecode.as_deref()
    }
}
impl StopTimecode {
    /// Creates a new builder-style object to manufacture [`StopTimecode`](crate::types::StopTimecode).
    pub fn builder() -> crate::types::builders::StopTimecodeBuilder {
        crate::types::builders::StopTimecodeBuilder::default()
    }
}

/// A builder for [`StopTimecode`](crate::types::StopTimecode).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopTimecodeBuilder {
    pub(crate) last_frame_clipping_behavior: ::std::option::Option<crate::types::LastFrameClippingBehavior>,
    pub(crate) timecode: ::std::option::Option<::std::string::String>,
}
impl StopTimecodeBuilder {
    /// If you specify a StopTimecode in an input (in order to clip the file), you can specify if you want the clip to exclude (the default) or include the frame specified by the timecode.
    pub fn last_frame_clipping_behavior(mut self, input: crate::types::LastFrameClippingBehavior) -> Self {
        self.last_frame_clipping_behavior = ::std::option::Option::Some(input);
        self
    }
    /// If you specify a StopTimecode in an input (in order to clip the file), you can specify if you want the clip to exclude (the default) or include the frame specified by the timecode.
    pub fn set_last_frame_clipping_behavior(mut self, input: ::std::option::Option<crate::types::LastFrameClippingBehavior>) -> Self {
        self.last_frame_clipping_behavior = input;
        self
    }
    /// If you specify a StopTimecode in an input (in order to clip the file), you can specify if you want the clip to exclude (the default) or include the frame specified by the timecode.
    pub fn get_last_frame_clipping_behavior(&self) -> &::std::option::Option<crate::types::LastFrameClippingBehavior> {
        &self.last_frame_clipping_behavior
    }
    /// The timecode for the frame where you want to stop the clip. Optional; if not specified, the clip continues to the end of the file. Enter the timecode as HH:MM:SS:FF or HH:MM:SS;FF.
    pub fn timecode(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timecode = ::std::option::Option::Some(input.into());
        self
    }
    /// The timecode for the frame where you want to stop the clip. Optional; if not specified, the clip continues to the end of the file. Enter the timecode as HH:MM:SS:FF or HH:MM:SS;FF.
    pub fn set_timecode(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timecode = input;
        self
    }
    /// The timecode for the frame where you want to stop the clip. Optional; if not specified, the clip continues to the end of the file. Enter the timecode as HH:MM:SS:FF or HH:MM:SS;FF.
    pub fn get_timecode(&self) -> &::std::option::Option<::std::string::String> {
        &self.timecode
    }
    /// Consumes the builder and constructs a [`StopTimecode`](crate::types::StopTimecode).
    pub fn build(self) -> crate::types::StopTimecode {
        crate::types::StopTimecode {
            last_frame_clipping_behavior: self.last_frame_clipping_behavior,
            timecode: self.timecode,
        }
    }
}
