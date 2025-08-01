// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Ignore this setting unless your input captions format is SCC. To have the service compensate for differing frame rates between your input captions and input video, specify the frame rate of the captions file. Specify this value as a fraction. For example, you might specify 24 / 1 for 24 fps, 25 / 1 for 25 fps, 24000 / 1001 for 23.976 fps, or 30000 / 1001 for 29.97 fps.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CaptionSourceFramerate {
    /// Specify the denominator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate numerator.
    pub framerate_denominator: ::std::option::Option<i32>,
    /// Specify the numerator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate denominator.
    pub framerate_numerator: ::std::option::Option<i32>,
}
impl CaptionSourceFramerate {
    /// Specify the denominator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate numerator.
    pub fn framerate_denominator(&self) -> ::std::option::Option<i32> {
        self.framerate_denominator
    }
    /// Specify the numerator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate denominator.
    pub fn framerate_numerator(&self) -> ::std::option::Option<i32> {
        self.framerate_numerator
    }
}
impl CaptionSourceFramerate {
    /// Creates a new builder-style object to manufacture [`CaptionSourceFramerate`](crate::types::CaptionSourceFramerate).
    pub fn builder() -> crate::types::builders::CaptionSourceFramerateBuilder {
        crate::types::builders::CaptionSourceFramerateBuilder::default()
    }
}

/// A builder for [`CaptionSourceFramerate`](crate::types::CaptionSourceFramerate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CaptionSourceFramerateBuilder {
    pub(crate) framerate_denominator: ::std::option::Option<i32>,
    pub(crate) framerate_numerator: ::std::option::Option<i32>,
}
impl CaptionSourceFramerateBuilder {
    /// Specify the denominator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate numerator.
    pub fn framerate_denominator(mut self, input: i32) -> Self {
        self.framerate_denominator = ::std::option::Option::Some(input);
        self
    }
    /// Specify the denominator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate numerator.
    pub fn set_framerate_denominator(mut self, input: ::std::option::Option<i32>) -> Self {
        self.framerate_denominator = input;
        self
    }
    /// Specify the denominator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate numerator.
    pub fn get_framerate_denominator(&self) -> &::std::option::Option<i32> {
        &self.framerate_denominator
    }
    /// Specify the numerator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate denominator.
    pub fn framerate_numerator(mut self, input: i32) -> Self {
        self.framerate_numerator = ::std::option::Option::Some(input);
        self
    }
    /// Specify the numerator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate denominator.
    pub fn set_framerate_numerator(mut self, input: ::std::option::Option<i32>) -> Self {
        self.framerate_numerator = input;
        self
    }
    /// Specify the numerator of the fraction that represents the frame rate for the setting Caption source frame rate. Use this setting along with the setting Framerate denominator.
    pub fn get_framerate_numerator(&self) -> &::std::option::Option<i32> {
        &self.framerate_numerator
    }
    /// Consumes the builder and constructs a [`CaptionSourceFramerate`](crate::types::CaptionSourceFramerate).
    pub fn build(self) -> crate::types::CaptionSourceFramerate {
        crate::types::CaptionSourceFramerate {
            framerate_denominator: self.framerate_denominator,
            framerate_numerator: self.framerate_numerator,
        }
    }
}
