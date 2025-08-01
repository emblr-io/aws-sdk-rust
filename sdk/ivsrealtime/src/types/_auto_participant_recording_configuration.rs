// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object specifying a configuration for individual participant recording.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoParticipantRecordingConfiguration {
    /// <p>ARN of the <code>StorageConfiguration</code> resource to use for individual participant recording. Default: <code>""</code> (empty string, no storage configuration is specified). Individual participant recording cannot be started unless a storage configuration is specified, when a <code>Stage</code> is created or updated. To disable individual participant recording, set this to <code>""</code>; other fields in this object will get reset to their defaults when sending <code>""</code>.</p>
    pub storage_configuration_arn: ::std::string::String,
    /// <p>Types of media to be recorded. Default: <code>AUDIO_VIDEO</code>.</p>
    pub media_types: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantRecordingMediaType>>,
    /// <p>A complex type that allows you to enable/disable the recording of thumbnails for individual participant recording and modify the interval at which thumbnails are generated for the live session.</p>
    pub thumbnail_configuration: ::std::option::Option<crate::types::ParticipantThumbnailConfiguration>,
    /// <p>If a stage publisher disconnects and then reconnects within the specified interval, the multiple recordings will be considered a single recording and merged together.</p>
    /// <p>The default value is 0, which disables merging.</p>
    pub recording_reconnect_window_seconds: i32,
    /// <p>HLS configuration object for individual participant recording.</p>
    pub hls_configuration: ::std::option::Option<crate::types::ParticipantRecordingHlsConfiguration>,
    /// <p>Optional field to disable replica participant recording. If this is set to <code>false</code> when a participant is a replica, replica participants are not recorded. Default: <code>true</code>.</p>
    pub record_participant_replicas: bool,
}
impl AutoParticipantRecordingConfiguration {
    /// <p>ARN of the <code>StorageConfiguration</code> resource to use for individual participant recording. Default: <code>""</code> (empty string, no storage configuration is specified). Individual participant recording cannot be started unless a storage configuration is specified, when a <code>Stage</code> is created or updated. To disable individual participant recording, set this to <code>""</code>; other fields in this object will get reset to their defaults when sending <code>""</code>.</p>
    pub fn storage_configuration_arn(&self) -> &str {
        use std::ops::Deref;
        self.storage_configuration_arn.deref()
    }
    /// <p>Types of media to be recorded. Default: <code>AUDIO_VIDEO</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.media_types.is_none()`.
    pub fn media_types(&self) -> &[crate::types::ParticipantRecordingMediaType] {
        self.media_types.as_deref().unwrap_or_default()
    }
    /// <p>A complex type that allows you to enable/disable the recording of thumbnails for individual participant recording and modify the interval at which thumbnails are generated for the live session.</p>
    pub fn thumbnail_configuration(&self) -> ::std::option::Option<&crate::types::ParticipantThumbnailConfiguration> {
        self.thumbnail_configuration.as_ref()
    }
    /// <p>If a stage publisher disconnects and then reconnects within the specified interval, the multiple recordings will be considered a single recording and merged together.</p>
    /// <p>The default value is 0, which disables merging.</p>
    pub fn recording_reconnect_window_seconds(&self) -> i32 {
        self.recording_reconnect_window_seconds
    }
    /// <p>HLS configuration object for individual participant recording.</p>
    pub fn hls_configuration(&self) -> ::std::option::Option<&crate::types::ParticipantRecordingHlsConfiguration> {
        self.hls_configuration.as_ref()
    }
    /// <p>Optional field to disable replica participant recording. If this is set to <code>false</code> when a participant is a replica, replica participants are not recorded. Default: <code>true</code>.</p>
    pub fn record_participant_replicas(&self) -> bool {
        self.record_participant_replicas
    }
}
impl AutoParticipantRecordingConfiguration {
    /// Creates a new builder-style object to manufacture [`AutoParticipantRecordingConfiguration`](crate::types::AutoParticipantRecordingConfiguration).
    pub fn builder() -> crate::types::builders::AutoParticipantRecordingConfigurationBuilder {
        crate::types::builders::AutoParticipantRecordingConfigurationBuilder::default()
    }
}

/// A builder for [`AutoParticipantRecordingConfiguration`](crate::types::AutoParticipantRecordingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoParticipantRecordingConfigurationBuilder {
    pub(crate) storage_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) media_types: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantRecordingMediaType>>,
    pub(crate) thumbnail_configuration: ::std::option::Option<crate::types::ParticipantThumbnailConfiguration>,
    pub(crate) recording_reconnect_window_seconds: ::std::option::Option<i32>,
    pub(crate) hls_configuration: ::std::option::Option<crate::types::ParticipantRecordingHlsConfiguration>,
    pub(crate) record_participant_replicas: ::std::option::Option<bool>,
}
impl AutoParticipantRecordingConfigurationBuilder {
    /// <p>ARN of the <code>StorageConfiguration</code> resource to use for individual participant recording. Default: <code>""</code> (empty string, no storage configuration is specified). Individual participant recording cannot be started unless a storage configuration is specified, when a <code>Stage</code> is created or updated. To disable individual participant recording, set this to <code>""</code>; other fields in this object will get reset to their defaults when sending <code>""</code>.</p>
    /// This field is required.
    pub fn storage_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.storage_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the <code>StorageConfiguration</code> resource to use for individual participant recording. Default: <code>""</code> (empty string, no storage configuration is specified). Individual participant recording cannot be started unless a storage configuration is specified, when a <code>Stage</code> is created or updated. To disable individual participant recording, set this to <code>""</code>; other fields in this object will get reset to their defaults when sending <code>""</code>.</p>
    pub fn set_storage_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.storage_configuration_arn = input;
        self
    }
    /// <p>ARN of the <code>StorageConfiguration</code> resource to use for individual participant recording. Default: <code>""</code> (empty string, no storage configuration is specified). Individual participant recording cannot be started unless a storage configuration is specified, when a <code>Stage</code> is created or updated. To disable individual participant recording, set this to <code>""</code>; other fields in this object will get reset to their defaults when sending <code>""</code>.</p>
    pub fn get_storage_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.storage_configuration_arn
    }
    /// Appends an item to `media_types`.
    ///
    /// To override the contents of this collection use [`set_media_types`](Self::set_media_types).
    ///
    /// <p>Types of media to be recorded. Default: <code>AUDIO_VIDEO</code>.</p>
    pub fn media_types(mut self, input: crate::types::ParticipantRecordingMediaType) -> Self {
        let mut v = self.media_types.unwrap_or_default();
        v.push(input);
        self.media_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Types of media to be recorded. Default: <code>AUDIO_VIDEO</code>.</p>
    pub fn set_media_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantRecordingMediaType>>) -> Self {
        self.media_types = input;
        self
    }
    /// <p>Types of media to be recorded. Default: <code>AUDIO_VIDEO</code>.</p>
    pub fn get_media_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParticipantRecordingMediaType>> {
        &self.media_types
    }
    /// <p>A complex type that allows you to enable/disable the recording of thumbnails for individual participant recording and modify the interval at which thumbnails are generated for the live session.</p>
    pub fn thumbnail_configuration(mut self, input: crate::types::ParticipantThumbnailConfiguration) -> Self {
        self.thumbnail_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that allows you to enable/disable the recording of thumbnails for individual participant recording and modify the interval at which thumbnails are generated for the live session.</p>
    pub fn set_thumbnail_configuration(mut self, input: ::std::option::Option<crate::types::ParticipantThumbnailConfiguration>) -> Self {
        self.thumbnail_configuration = input;
        self
    }
    /// <p>A complex type that allows you to enable/disable the recording of thumbnails for individual participant recording and modify the interval at which thumbnails are generated for the live session.</p>
    pub fn get_thumbnail_configuration(&self) -> &::std::option::Option<crate::types::ParticipantThumbnailConfiguration> {
        &self.thumbnail_configuration
    }
    /// <p>If a stage publisher disconnects and then reconnects within the specified interval, the multiple recordings will be considered a single recording and merged together.</p>
    /// <p>The default value is 0, which disables merging.</p>
    pub fn recording_reconnect_window_seconds(mut self, input: i32) -> Self {
        self.recording_reconnect_window_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>If a stage publisher disconnects and then reconnects within the specified interval, the multiple recordings will be considered a single recording and merged together.</p>
    /// <p>The default value is 0, which disables merging.</p>
    pub fn set_recording_reconnect_window_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.recording_reconnect_window_seconds = input;
        self
    }
    /// <p>If a stage publisher disconnects and then reconnects within the specified interval, the multiple recordings will be considered a single recording and merged together.</p>
    /// <p>The default value is 0, which disables merging.</p>
    pub fn get_recording_reconnect_window_seconds(&self) -> &::std::option::Option<i32> {
        &self.recording_reconnect_window_seconds
    }
    /// <p>HLS configuration object for individual participant recording.</p>
    pub fn hls_configuration(mut self, input: crate::types::ParticipantRecordingHlsConfiguration) -> Self {
        self.hls_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>HLS configuration object for individual participant recording.</p>
    pub fn set_hls_configuration(mut self, input: ::std::option::Option<crate::types::ParticipantRecordingHlsConfiguration>) -> Self {
        self.hls_configuration = input;
        self
    }
    /// <p>HLS configuration object for individual participant recording.</p>
    pub fn get_hls_configuration(&self) -> &::std::option::Option<crate::types::ParticipantRecordingHlsConfiguration> {
        &self.hls_configuration
    }
    /// <p>Optional field to disable replica participant recording. If this is set to <code>false</code> when a participant is a replica, replica participants are not recorded. Default: <code>true</code>.</p>
    pub fn record_participant_replicas(mut self, input: bool) -> Self {
        self.record_participant_replicas = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional field to disable replica participant recording. If this is set to <code>false</code> when a participant is a replica, replica participants are not recorded. Default: <code>true</code>.</p>
    pub fn set_record_participant_replicas(mut self, input: ::std::option::Option<bool>) -> Self {
        self.record_participant_replicas = input;
        self
    }
    /// <p>Optional field to disable replica participant recording. If this is set to <code>false</code> when a participant is a replica, replica participants are not recorded. Default: <code>true</code>.</p>
    pub fn get_record_participant_replicas(&self) -> &::std::option::Option<bool> {
        &self.record_participant_replicas
    }
    /// Consumes the builder and constructs a [`AutoParticipantRecordingConfiguration`](crate::types::AutoParticipantRecordingConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`storage_configuration_arn`](crate::types::builders::AutoParticipantRecordingConfigurationBuilder::storage_configuration_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::AutoParticipantRecordingConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AutoParticipantRecordingConfiguration {
            storage_configuration_arn: self.storage_configuration_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "storage_configuration_arn",
                    "storage_configuration_arn was not specified but it is required when building AutoParticipantRecordingConfiguration",
                )
            })?,
            media_types: self.media_types,
            thumbnail_configuration: self.thumbnail_configuration,
            recording_reconnect_window_seconds: self.recording_reconnect_window_seconds.unwrap_or_default(),
            hls_configuration: self.hls_configuration,
            record_participant_replicas: self.record_participant_replicas.unwrap_or_default(),
        })
    }
}
