// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Audio Only Hls Settings
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioOnlyHlsSettings {
    /// Specifies the group to which the audio Rendition belongs.
    pub audio_group_id: ::std::option::Option<::std::string::String>,
    /// Optional. Specifies the .jpg or .png image to use as the cover art for an audio-only output. We recommend a low bit-size file because the image increases the output audio bandwidth. The image is attached to the audio as an ID3 tag, frame type APIC, picture type 0x10, as per the "ID3 tag version 2.4.0 - Native Frames" standard.
    pub audio_only_image: ::std::option::Option<crate::types::InputLocation>,
    /// Four types of audio-only tracks are supported: Audio-Only Variant Stream The client can play back this audio-only stream instead of video in low-bandwidth scenarios. Represented as an EXT-X-STREAM-INF in the HLS manifest. Alternate Audio, Auto Select, Default Alternate rendition that the client should try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=YES, AUTOSELECT=YES Alternate Audio, Auto Select, Not Default Alternate rendition that the client may try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=YES Alternate Audio, not Auto Select Alternate rendition that the client will not try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=NO
    pub audio_track_type: ::std::option::Option<crate::types::AudioOnlyHlsTrackType>,
    /// Specifies the segment type.
    pub segment_type: ::std::option::Option<crate::types::AudioOnlyHlsSegmentType>,
}
impl AudioOnlyHlsSettings {
    /// Specifies the group to which the audio Rendition belongs.
    pub fn audio_group_id(&self) -> ::std::option::Option<&str> {
        self.audio_group_id.as_deref()
    }
    /// Optional. Specifies the .jpg or .png image to use as the cover art for an audio-only output. We recommend a low bit-size file because the image increases the output audio bandwidth. The image is attached to the audio as an ID3 tag, frame type APIC, picture type 0x10, as per the "ID3 tag version 2.4.0 - Native Frames" standard.
    pub fn audio_only_image(&self) -> ::std::option::Option<&crate::types::InputLocation> {
        self.audio_only_image.as_ref()
    }
    /// Four types of audio-only tracks are supported: Audio-Only Variant Stream The client can play back this audio-only stream instead of video in low-bandwidth scenarios. Represented as an EXT-X-STREAM-INF in the HLS manifest. Alternate Audio, Auto Select, Default Alternate rendition that the client should try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=YES, AUTOSELECT=YES Alternate Audio, Auto Select, Not Default Alternate rendition that the client may try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=YES Alternate Audio, not Auto Select Alternate rendition that the client will not try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=NO
    pub fn audio_track_type(&self) -> ::std::option::Option<&crate::types::AudioOnlyHlsTrackType> {
        self.audio_track_type.as_ref()
    }
    /// Specifies the segment type.
    pub fn segment_type(&self) -> ::std::option::Option<&crate::types::AudioOnlyHlsSegmentType> {
        self.segment_type.as_ref()
    }
}
impl AudioOnlyHlsSettings {
    /// Creates a new builder-style object to manufacture [`AudioOnlyHlsSettings`](crate::types::AudioOnlyHlsSettings).
    pub fn builder() -> crate::types::builders::AudioOnlyHlsSettingsBuilder {
        crate::types::builders::AudioOnlyHlsSettingsBuilder::default()
    }
}

/// A builder for [`AudioOnlyHlsSettings`](crate::types::AudioOnlyHlsSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioOnlyHlsSettingsBuilder {
    pub(crate) audio_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) audio_only_image: ::std::option::Option<crate::types::InputLocation>,
    pub(crate) audio_track_type: ::std::option::Option<crate::types::AudioOnlyHlsTrackType>,
    pub(crate) segment_type: ::std::option::Option<crate::types::AudioOnlyHlsSegmentType>,
}
impl AudioOnlyHlsSettingsBuilder {
    /// Specifies the group to which the audio Rendition belongs.
    pub fn audio_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.audio_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// Specifies the group to which the audio Rendition belongs.
    pub fn set_audio_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.audio_group_id = input;
        self
    }
    /// Specifies the group to which the audio Rendition belongs.
    pub fn get_audio_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.audio_group_id
    }
    /// Optional. Specifies the .jpg or .png image to use as the cover art for an audio-only output. We recommend a low bit-size file because the image increases the output audio bandwidth. The image is attached to the audio as an ID3 tag, frame type APIC, picture type 0x10, as per the "ID3 tag version 2.4.0 - Native Frames" standard.
    pub fn audio_only_image(mut self, input: crate::types::InputLocation) -> Self {
        self.audio_only_image = ::std::option::Option::Some(input);
        self
    }
    /// Optional. Specifies the .jpg or .png image to use as the cover art for an audio-only output. We recommend a low bit-size file because the image increases the output audio bandwidth. The image is attached to the audio as an ID3 tag, frame type APIC, picture type 0x10, as per the "ID3 tag version 2.4.0 - Native Frames" standard.
    pub fn set_audio_only_image(mut self, input: ::std::option::Option<crate::types::InputLocation>) -> Self {
        self.audio_only_image = input;
        self
    }
    /// Optional. Specifies the .jpg or .png image to use as the cover art for an audio-only output. We recommend a low bit-size file because the image increases the output audio bandwidth. The image is attached to the audio as an ID3 tag, frame type APIC, picture type 0x10, as per the "ID3 tag version 2.4.0 - Native Frames" standard.
    pub fn get_audio_only_image(&self) -> &::std::option::Option<crate::types::InputLocation> {
        &self.audio_only_image
    }
    /// Four types of audio-only tracks are supported: Audio-Only Variant Stream The client can play back this audio-only stream instead of video in low-bandwidth scenarios. Represented as an EXT-X-STREAM-INF in the HLS manifest. Alternate Audio, Auto Select, Default Alternate rendition that the client should try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=YES, AUTOSELECT=YES Alternate Audio, Auto Select, Not Default Alternate rendition that the client may try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=YES Alternate Audio, not Auto Select Alternate rendition that the client will not try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=NO
    pub fn audio_track_type(mut self, input: crate::types::AudioOnlyHlsTrackType) -> Self {
        self.audio_track_type = ::std::option::Option::Some(input);
        self
    }
    /// Four types of audio-only tracks are supported: Audio-Only Variant Stream The client can play back this audio-only stream instead of video in low-bandwidth scenarios. Represented as an EXT-X-STREAM-INF in the HLS manifest. Alternate Audio, Auto Select, Default Alternate rendition that the client should try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=YES, AUTOSELECT=YES Alternate Audio, Auto Select, Not Default Alternate rendition that the client may try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=YES Alternate Audio, not Auto Select Alternate rendition that the client will not try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=NO
    pub fn set_audio_track_type(mut self, input: ::std::option::Option<crate::types::AudioOnlyHlsTrackType>) -> Self {
        self.audio_track_type = input;
        self
    }
    /// Four types of audio-only tracks are supported: Audio-Only Variant Stream The client can play back this audio-only stream instead of video in low-bandwidth scenarios. Represented as an EXT-X-STREAM-INF in the HLS manifest. Alternate Audio, Auto Select, Default Alternate rendition that the client should try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=YES, AUTOSELECT=YES Alternate Audio, Auto Select, Not Default Alternate rendition that the client may try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=YES Alternate Audio, not Auto Select Alternate rendition that the client will not try to play back by default. Represented as an EXT-X-MEDIA in the HLS manifest with DEFAULT=NO, AUTOSELECT=NO
    pub fn get_audio_track_type(&self) -> &::std::option::Option<crate::types::AudioOnlyHlsTrackType> {
        &self.audio_track_type
    }
    /// Specifies the segment type.
    pub fn segment_type(mut self, input: crate::types::AudioOnlyHlsSegmentType) -> Self {
        self.segment_type = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the segment type.
    pub fn set_segment_type(mut self, input: ::std::option::Option<crate::types::AudioOnlyHlsSegmentType>) -> Self {
        self.segment_type = input;
        self
    }
    /// Specifies the segment type.
    pub fn get_segment_type(&self) -> &::std::option::Option<crate::types::AudioOnlyHlsSegmentType> {
        &self.segment_type
    }
    /// Consumes the builder and constructs a [`AudioOnlyHlsSettings`](crate::types::AudioOnlyHlsSettings).
    pub fn build(self) -> crate::types::AudioOnlyHlsSettings {
        crate::types::AudioOnlyHlsSettings {
            audio_group_id: self.audio_group_id,
            audio_only_image: self.audio_only_image,
            audio_track_type: self.audio_track_type,
            segment_type: self.segment_type,
        }
    }
}
