// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing a configuration of thumbnails for recorded video from an individual participant.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParticipantThumbnailConfiguration {
    /// <p>The targeted thumbnail-generation interval in seconds. This is configurable only if <code>recordingMode</code> is <code>INTERVAL</code>. Default: 60.</p>
    pub target_interval_seconds: ::std::option::Option<i32>,
    /// <p>Indicates the format in which thumbnails are recorded. <code>SEQUENTIAL</code> records all generated thumbnails in a serial manner, to the media/thumbnails/high directory. <code>LATEST</code> saves the latest thumbnail in media/latest_thumbnail/high/thumb.jpg and overwrites it at the interval specified by <code>targetIntervalSeconds</code>. You can enable both <code>SEQUENTIAL</code> and <code>LATEST</code>. Default: <code>SEQUENTIAL</code>.</p>
    pub storage: ::std::option::Option<::std::vec::Vec<crate::types::ThumbnailStorageType>>,
    /// <p>Thumbnail recording mode. Default: <code>DISABLED</code>.</p>
    pub recording_mode: ::std::option::Option<crate::types::ThumbnailRecordingMode>,
}
impl ParticipantThumbnailConfiguration {
    /// <p>The targeted thumbnail-generation interval in seconds. This is configurable only if <code>recordingMode</code> is <code>INTERVAL</code>. Default: 60.</p>
    pub fn target_interval_seconds(&self) -> ::std::option::Option<i32> {
        self.target_interval_seconds
    }
    /// <p>Indicates the format in which thumbnails are recorded. <code>SEQUENTIAL</code> records all generated thumbnails in a serial manner, to the media/thumbnails/high directory. <code>LATEST</code> saves the latest thumbnail in media/latest_thumbnail/high/thumb.jpg and overwrites it at the interval specified by <code>targetIntervalSeconds</code>. You can enable both <code>SEQUENTIAL</code> and <code>LATEST</code>. Default: <code>SEQUENTIAL</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.storage.is_none()`.
    pub fn storage(&self) -> &[crate::types::ThumbnailStorageType] {
        self.storage.as_deref().unwrap_or_default()
    }
    /// <p>Thumbnail recording mode. Default: <code>DISABLED</code>.</p>
    pub fn recording_mode(&self) -> ::std::option::Option<&crate::types::ThumbnailRecordingMode> {
        self.recording_mode.as_ref()
    }
}
impl ParticipantThumbnailConfiguration {
    /// Creates a new builder-style object to manufacture [`ParticipantThumbnailConfiguration`](crate::types::ParticipantThumbnailConfiguration).
    pub fn builder() -> crate::types::builders::ParticipantThumbnailConfigurationBuilder {
        crate::types::builders::ParticipantThumbnailConfigurationBuilder::default()
    }
}

/// A builder for [`ParticipantThumbnailConfiguration`](crate::types::ParticipantThumbnailConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParticipantThumbnailConfigurationBuilder {
    pub(crate) target_interval_seconds: ::std::option::Option<i32>,
    pub(crate) storage: ::std::option::Option<::std::vec::Vec<crate::types::ThumbnailStorageType>>,
    pub(crate) recording_mode: ::std::option::Option<crate::types::ThumbnailRecordingMode>,
}
impl ParticipantThumbnailConfigurationBuilder {
    /// <p>The targeted thumbnail-generation interval in seconds. This is configurable only if <code>recordingMode</code> is <code>INTERVAL</code>. Default: 60.</p>
    pub fn target_interval_seconds(mut self, input: i32) -> Self {
        self.target_interval_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The targeted thumbnail-generation interval in seconds. This is configurable only if <code>recordingMode</code> is <code>INTERVAL</code>. Default: 60.</p>
    pub fn set_target_interval_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.target_interval_seconds = input;
        self
    }
    /// <p>The targeted thumbnail-generation interval in seconds. This is configurable only if <code>recordingMode</code> is <code>INTERVAL</code>. Default: 60.</p>
    pub fn get_target_interval_seconds(&self) -> &::std::option::Option<i32> {
        &self.target_interval_seconds
    }
    /// Appends an item to `storage`.
    ///
    /// To override the contents of this collection use [`set_storage`](Self::set_storage).
    ///
    /// <p>Indicates the format in which thumbnails are recorded. <code>SEQUENTIAL</code> records all generated thumbnails in a serial manner, to the media/thumbnails/high directory. <code>LATEST</code> saves the latest thumbnail in media/latest_thumbnail/high/thumb.jpg and overwrites it at the interval specified by <code>targetIntervalSeconds</code>. You can enable both <code>SEQUENTIAL</code> and <code>LATEST</code>. Default: <code>SEQUENTIAL</code>.</p>
    pub fn storage(mut self, input: crate::types::ThumbnailStorageType) -> Self {
        let mut v = self.storage.unwrap_or_default();
        v.push(input);
        self.storage = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the format in which thumbnails are recorded. <code>SEQUENTIAL</code> records all generated thumbnails in a serial manner, to the media/thumbnails/high directory. <code>LATEST</code> saves the latest thumbnail in media/latest_thumbnail/high/thumb.jpg and overwrites it at the interval specified by <code>targetIntervalSeconds</code>. You can enable both <code>SEQUENTIAL</code> and <code>LATEST</code>. Default: <code>SEQUENTIAL</code>.</p>
    pub fn set_storage(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ThumbnailStorageType>>) -> Self {
        self.storage = input;
        self
    }
    /// <p>Indicates the format in which thumbnails are recorded. <code>SEQUENTIAL</code> records all generated thumbnails in a serial manner, to the media/thumbnails/high directory. <code>LATEST</code> saves the latest thumbnail in media/latest_thumbnail/high/thumb.jpg and overwrites it at the interval specified by <code>targetIntervalSeconds</code>. You can enable both <code>SEQUENTIAL</code> and <code>LATEST</code>. Default: <code>SEQUENTIAL</code>.</p>
    pub fn get_storage(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ThumbnailStorageType>> {
        &self.storage
    }
    /// <p>Thumbnail recording mode. Default: <code>DISABLED</code>.</p>
    pub fn recording_mode(mut self, input: crate::types::ThumbnailRecordingMode) -> Self {
        self.recording_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Thumbnail recording mode. Default: <code>DISABLED</code>.</p>
    pub fn set_recording_mode(mut self, input: ::std::option::Option<crate::types::ThumbnailRecordingMode>) -> Self {
        self.recording_mode = input;
        self
    }
    /// <p>Thumbnail recording mode. Default: <code>DISABLED</code>.</p>
    pub fn get_recording_mode(&self) -> &::std::option::Option<crate::types::ThumbnailRecordingMode> {
        &self.recording_mode
    }
    /// Consumes the builder and constructs a [`ParticipantThumbnailConfiguration`](crate::types::ParticipantThumbnailConfiguration).
    pub fn build(self) -> crate::types::ParticipantThumbnailConfiguration {
        crate::types::ParticipantThumbnailConfiguration {
            target_interval_seconds: self.target_interval_seconds,
            storage: self.storage,
            recording_mode: self.recording_mode,
        }
    }
}
