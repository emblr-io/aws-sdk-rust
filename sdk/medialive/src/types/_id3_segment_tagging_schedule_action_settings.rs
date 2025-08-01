// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings for the action to insert ID3 metadata in every segment, in applicable output groups.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Id3SegmentTaggingScheduleActionSettings {
    /// Complete this parameter if you want to specify the entire ID3 metadata. Enter a base64 string that contains one or more fully formed ID3 tags, according to the ID3 specification: http://id3.org/id3v2.4.0-structure
    pub id3: ::std::option::Option<::std::string::String>,
    /// Complete this parameter if you want to specify only the metadata, not the entire frame. MediaLive will insert the metadata in a TXXX frame. Enter the value as plain text. You can include standard MediaLive variable data such as the current segment number.
    pub tag: ::std::option::Option<::std::string::String>,
}
impl Id3SegmentTaggingScheduleActionSettings {
    /// Complete this parameter if you want to specify the entire ID3 metadata. Enter a base64 string that contains one or more fully formed ID3 tags, according to the ID3 specification: http://id3.org/id3v2.4.0-structure
    pub fn id3(&self) -> ::std::option::Option<&str> {
        self.id3.as_deref()
    }
    /// Complete this parameter if you want to specify only the metadata, not the entire frame. MediaLive will insert the metadata in a TXXX frame. Enter the value as plain text. You can include standard MediaLive variable data such as the current segment number.
    pub fn tag(&self) -> ::std::option::Option<&str> {
        self.tag.as_deref()
    }
}
impl Id3SegmentTaggingScheduleActionSettings {
    /// Creates a new builder-style object to manufacture [`Id3SegmentTaggingScheduleActionSettings`](crate::types::Id3SegmentTaggingScheduleActionSettings).
    pub fn builder() -> crate::types::builders::Id3SegmentTaggingScheduleActionSettingsBuilder {
        crate::types::builders::Id3SegmentTaggingScheduleActionSettingsBuilder::default()
    }
}

/// A builder for [`Id3SegmentTaggingScheduleActionSettings`](crate::types::Id3SegmentTaggingScheduleActionSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Id3SegmentTaggingScheduleActionSettingsBuilder {
    pub(crate) id3: ::std::option::Option<::std::string::String>,
    pub(crate) tag: ::std::option::Option<::std::string::String>,
}
impl Id3SegmentTaggingScheduleActionSettingsBuilder {
    /// Complete this parameter if you want to specify the entire ID3 metadata. Enter a base64 string that contains one or more fully formed ID3 tags, according to the ID3 specification: http://id3.org/id3v2.4.0-structure
    pub fn id3(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id3 = ::std::option::Option::Some(input.into());
        self
    }
    /// Complete this parameter if you want to specify the entire ID3 metadata. Enter a base64 string that contains one or more fully formed ID3 tags, according to the ID3 specification: http://id3.org/id3v2.4.0-structure
    pub fn set_id3(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id3 = input;
        self
    }
    /// Complete this parameter if you want to specify the entire ID3 metadata. Enter a base64 string that contains one or more fully formed ID3 tags, according to the ID3 specification: http://id3.org/id3v2.4.0-structure
    pub fn get_id3(&self) -> &::std::option::Option<::std::string::String> {
        &self.id3
    }
    /// Complete this parameter if you want to specify only the metadata, not the entire frame. MediaLive will insert the metadata in a TXXX frame. Enter the value as plain text. You can include standard MediaLive variable data such as the current segment number.
    pub fn tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tag = ::std::option::Option::Some(input.into());
        self
    }
    /// Complete this parameter if you want to specify only the metadata, not the entire frame. MediaLive will insert the metadata in a TXXX frame. Enter the value as plain text. You can include standard MediaLive variable data such as the current segment number.
    pub fn set_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tag = input;
        self
    }
    /// Complete this parameter if you want to specify only the metadata, not the entire frame. MediaLive will insert the metadata in a TXXX frame. Enter the value as plain text. You can include standard MediaLive variable data such as the current segment number.
    pub fn get_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.tag
    }
    /// Consumes the builder and constructs a [`Id3SegmentTaggingScheduleActionSettings`](crate::types::Id3SegmentTaggingScheduleActionSettings).
    pub fn build(self) -> crate::types::Id3SegmentTaggingScheduleActionSettings {
        crate::types::Id3SegmentTaggingScheduleActionSettings {
            id3: self.id3,
            tag: self.tag,
        }
    }
}
