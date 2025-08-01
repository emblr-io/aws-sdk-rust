// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Audio Watermark Settings
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioWatermarkSettings {
    /// Settings to configure Nielsen Watermarks in the audio encode
    pub nielsen_watermarks_settings: ::std::option::Option<crate::types::NielsenWatermarksSettings>,
}
impl AudioWatermarkSettings {
    /// Settings to configure Nielsen Watermarks in the audio encode
    pub fn nielsen_watermarks_settings(&self) -> ::std::option::Option<&crate::types::NielsenWatermarksSettings> {
        self.nielsen_watermarks_settings.as_ref()
    }
}
impl AudioWatermarkSettings {
    /// Creates a new builder-style object to manufacture [`AudioWatermarkSettings`](crate::types::AudioWatermarkSettings).
    pub fn builder() -> crate::types::builders::AudioWatermarkSettingsBuilder {
        crate::types::builders::AudioWatermarkSettingsBuilder::default()
    }
}

/// A builder for [`AudioWatermarkSettings`](crate::types::AudioWatermarkSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioWatermarkSettingsBuilder {
    pub(crate) nielsen_watermarks_settings: ::std::option::Option<crate::types::NielsenWatermarksSettings>,
}
impl AudioWatermarkSettingsBuilder {
    /// Settings to configure Nielsen Watermarks in the audio encode
    pub fn nielsen_watermarks_settings(mut self, input: crate::types::NielsenWatermarksSettings) -> Self {
        self.nielsen_watermarks_settings = ::std::option::Option::Some(input);
        self
    }
    /// Settings to configure Nielsen Watermarks in the audio encode
    pub fn set_nielsen_watermarks_settings(mut self, input: ::std::option::Option<crate::types::NielsenWatermarksSettings>) -> Self {
        self.nielsen_watermarks_settings = input;
        self
    }
    /// Settings to configure Nielsen Watermarks in the audio encode
    pub fn get_nielsen_watermarks_settings(&self) -> &::std::option::Option<crate::types::NielsenWatermarksSettings> {
        &self.nielsen_watermarks_settings
    }
    /// Consumes the builder and constructs a [`AudioWatermarkSettings`](crate::types::AudioWatermarkSettings).
    pub fn build(self) -> crate::types::AudioWatermarkSettings {
        crate::types::AudioWatermarkSettings {
            nielsen_watermarks_settings: self.nielsen_watermarks_settings,
        }
    }
}
