// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing a configuration of participant HLS recordings for individual participant recording.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParticipantRecordingHlsConfiguration {
    /// <p>Defines the target duration for recorded segments generated when recording a stage participant. Segments may have durations longer than the specified value when needed to ensure each segment begins with a keyframe. Default: 6.</p>
    pub target_segment_duration_seconds: ::std::option::Option<i32>,
}
impl ParticipantRecordingHlsConfiguration {
    /// <p>Defines the target duration for recorded segments generated when recording a stage participant. Segments may have durations longer than the specified value when needed to ensure each segment begins with a keyframe. Default: 6.</p>
    pub fn target_segment_duration_seconds(&self) -> ::std::option::Option<i32> {
        self.target_segment_duration_seconds
    }
}
impl ParticipantRecordingHlsConfiguration {
    /// Creates a new builder-style object to manufacture [`ParticipantRecordingHlsConfiguration`](crate::types::ParticipantRecordingHlsConfiguration).
    pub fn builder() -> crate::types::builders::ParticipantRecordingHlsConfigurationBuilder {
        crate::types::builders::ParticipantRecordingHlsConfigurationBuilder::default()
    }
}

/// A builder for [`ParticipantRecordingHlsConfiguration`](crate::types::ParticipantRecordingHlsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParticipantRecordingHlsConfigurationBuilder {
    pub(crate) target_segment_duration_seconds: ::std::option::Option<i32>,
}
impl ParticipantRecordingHlsConfigurationBuilder {
    /// <p>Defines the target duration for recorded segments generated when recording a stage participant. Segments may have durations longer than the specified value when needed to ensure each segment begins with a keyframe. Default: 6.</p>
    pub fn target_segment_duration_seconds(mut self, input: i32) -> Self {
        self.target_segment_duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the target duration for recorded segments generated when recording a stage participant. Segments may have durations longer than the specified value when needed to ensure each segment begins with a keyframe. Default: 6.</p>
    pub fn set_target_segment_duration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.target_segment_duration_seconds = input;
        self
    }
    /// <p>Defines the target duration for recorded segments generated when recording a stage participant. Segments may have durations longer than the specified value when needed to ensure each segment begins with a keyframe. Default: 6.</p>
    pub fn get_target_segment_duration_seconds(&self) -> &::std::option::Option<i32> {
        &self.target_segment_duration_seconds
    }
    /// Consumes the builder and constructs a [`ParticipantRecordingHlsConfiguration`](crate::types::ParticipantRecordingHlsConfiguration).
    pub fn build(self) -> crate::types::ParticipantRecordingHlsConfiguration {
        crate::types::ParticipantRecordingHlsConfiguration {
            target_segment_duration_seconds: self.target_segment_duration_seconds,
        }
    }
}
