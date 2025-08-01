// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// One audio configuration that specifies the format for one audio pair that the device produces as output.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputDeviceUhdAudioChannelPairConfig {
    /// The ID for one audio pair configuration, a value from 1 to 8.
    pub id: ::std::option::Option<i32>,
    /// The profile for one audio pair configuration. This property describes one audio configuration in the format (rate control algorithm)-(codec)_(quality)-(bitrate in bytes). For example, CBR-AAC_HQ-192000. Or DISABLED, in which case the device won't produce audio for this pair.
    pub profile: ::std::option::Option<crate::types::InputDeviceUhdAudioChannelPairProfile>,
}
impl InputDeviceUhdAudioChannelPairConfig {
    /// The ID for one audio pair configuration, a value from 1 to 8.
    pub fn id(&self) -> ::std::option::Option<i32> {
        self.id
    }
    /// The profile for one audio pair configuration. This property describes one audio configuration in the format (rate control algorithm)-(codec)_(quality)-(bitrate in bytes). For example, CBR-AAC_HQ-192000. Or DISABLED, in which case the device won't produce audio for this pair.
    pub fn profile(&self) -> ::std::option::Option<&crate::types::InputDeviceUhdAudioChannelPairProfile> {
        self.profile.as_ref()
    }
}
impl InputDeviceUhdAudioChannelPairConfig {
    /// Creates a new builder-style object to manufacture [`InputDeviceUhdAudioChannelPairConfig`](crate::types::InputDeviceUhdAudioChannelPairConfig).
    pub fn builder() -> crate::types::builders::InputDeviceUhdAudioChannelPairConfigBuilder {
        crate::types::builders::InputDeviceUhdAudioChannelPairConfigBuilder::default()
    }
}

/// A builder for [`InputDeviceUhdAudioChannelPairConfig`](crate::types::InputDeviceUhdAudioChannelPairConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputDeviceUhdAudioChannelPairConfigBuilder {
    pub(crate) id: ::std::option::Option<i32>,
    pub(crate) profile: ::std::option::Option<crate::types::InputDeviceUhdAudioChannelPairProfile>,
}
impl InputDeviceUhdAudioChannelPairConfigBuilder {
    /// The ID for one audio pair configuration, a value from 1 to 8.
    pub fn id(mut self, input: i32) -> Self {
        self.id = ::std::option::Option::Some(input);
        self
    }
    /// The ID for one audio pair configuration, a value from 1 to 8.
    pub fn set_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.id = input;
        self
    }
    /// The ID for one audio pair configuration, a value from 1 to 8.
    pub fn get_id(&self) -> &::std::option::Option<i32> {
        &self.id
    }
    /// The profile for one audio pair configuration. This property describes one audio configuration in the format (rate control algorithm)-(codec)_(quality)-(bitrate in bytes). For example, CBR-AAC_HQ-192000. Or DISABLED, in which case the device won't produce audio for this pair.
    pub fn profile(mut self, input: crate::types::InputDeviceUhdAudioChannelPairProfile) -> Self {
        self.profile = ::std::option::Option::Some(input);
        self
    }
    /// The profile for one audio pair configuration. This property describes one audio configuration in the format (rate control algorithm)-(codec)_(quality)-(bitrate in bytes). For example, CBR-AAC_HQ-192000. Or DISABLED, in which case the device won't produce audio for this pair.
    pub fn set_profile(mut self, input: ::std::option::Option<crate::types::InputDeviceUhdAudioChannelPairProfile>) -> Self {
        self.profile = input;
        self
    }
    /// The profile for one audio pair configuration. This property describes one audio configuration in the format (rate control algorithm)-(codec)_(quality)-(bitrate in bytes). For example, CBR-AAC_HQ-192000. Or DISABLED, in which case the device won't produce audio for this pair.
    pub fn get_profile(&self) -> &::std::option::Option<crate::types::InputDeviceUhdAudioChannelPairProfile> {
        &self.profile
    }
    /// Consumes the builder and constructs a [`InputDeviceUhdAudioChannelPairConfig`](crate::types::InputDeviceUhdAudioChannelPairConfig).
    pub fn build(self) -> crate::types::InputDeviceUhdAudioChannelPairConfig {
        crate::types::InputDeviceUhdAudioChannelPairConfig {
            id: self.id,
            profile: self.profile,
        }
    }
}
