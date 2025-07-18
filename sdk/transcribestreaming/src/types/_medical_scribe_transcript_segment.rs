// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a set of transcription results, along with additional information of the segment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MedicalScribeTranscriptSegment {
    /// <p>The identifier of the segment.</p>
    pub segment_id: ::std::option::Option<::std::string::String>,
    /// <p>The start time, in milliseconds, of the segment.</p>
    pub begin_audio_time: f64,
    /// <p>The end time, in milliseconds, of the segment.</p>
    pub end_audio_time: f64,
    /// <p>Contains transcribed text of the segment.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>Contains words, phrases, or punctuation marks in your segment.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::MedicalScribeTranscriptItem>>,
    /// <p>Indicates if the segment is complete.</p>
    /// <p>If <code>IsPartial</code> is <code>true</code>, the segment is not complete. If <code>IsPartial</code> is <code>false</code>, the segment is complete.</p>
    pub is_partial: bool,
    /// <p>Indicates which audio channel is associated with the <code>MedicalScribeTranscriptSegment</code>.</p>
    /// <p>If <code>MedicalScribeChannelDefinition</code> is not provided in the <code>MedicalScribeConfigurationEvent</code>, then this field will not be included.</p>
    pub channel_id: ::std::option::Option<::std::string::String>,
}
impl MedicalScribeTranscriptSegment {
    /// <p>The identifier of the segment.</p>
    pub fn segment_id(&self) -> ::std::option::Option<&str> {
        self.segment_id.as_deref()
    }
    /// <p>The start time, in milliseconds, of the segment.</p>
    pub fn begin_audio_time(&self) -> f64 {
        self.begin_audio_time
    }
    /// <p>The end time, in milliseconds, of the segment.</p>
    pub fn end_audio_time(&self) -> f64 {
        self.end_audio_time
    }
    /// <p>Contains transcribed text of the segment.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>Contains words, phrases, or punctuation marks in your segment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::MedicalScribeTranscriptItem] {
        self.items.as_deref().unwrap_or_default()
    }
    /// <p>Indicates if the segment is complete.</p>
    /// <p>If <code>IsPartial</code> is <code>true</code>, the segment is not complete. If <code>IsPartial</code> is <code>false</code>, the segment is complete.</p>
    pub fn is_partial(&self) -> bool {
        self.is_partial
    }
    /// <p>Indicates which audio channel is associated with the <code>MedicalScribeTranscriptSegment</code>.</p>
    /// <p>If <code>MedicalScribeChannelDefinition</code> is not provided in the <code>MedicalScribeConfigurationEvent</code>, then this field will not be included.</p>
    pub fn channel_id(&self) -> ::std::option::Option<&str> {
        self.channel_id.as_deref()
    }
}
impl MedicalScribeTranscriptSegment {
    /// Creates a new builder-style object to manufacture [`MedicalScribeTranscriptSegment`](crate::types::MedicalScribeTranscriptSegment).
    pub fn builder() -> crate::types::builders::MedicalScribeTranscriptSegmentBuilder {
        crate::types::builders::MedicalScribeTranscriptSegmentBuilder::default()
    }
}

/// A builder for [`MedicalScribeTranscriptSegment`](crate::types::MedicalScribeTranscriptSegment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MedicalScribeTranscriptSegmentBuilder {
    pub(crate) segment_id: ::std::option::Option<::std::string::String>,
    pub(crate) begin_audio_time: ::std::option::Option<f64>,
    pub(crate) end_audio_time: ::std::option::Option<f64>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::MedicalScribeTranscriptItem>>,
    pub(crate) is_partial: ::std::option::Option<bool>,
    pub(crate) channel_id: ::std::option::Option<::std::string::String>,
}
impl MedicalScribeTranscriptSegmentBuilder {
    /// <p>The identifier of the segment.</p>
    pub fn segment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.segment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the segment.</p>
    pub fn set_segment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.segment_id = input;
        self
    }
    /// <p>The identifier of the segment.</p>
    pub fn get_segment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.segment_id
    }
    /// <p>The start time, in milliseconds, of the segment.</p>
    pub fn begin_audio_time(mut self, input: f64) -> Self {
        self.begin_audio_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time, in milliseconds, of the segment.</p>
    pub fn set_begin_audio_time(mut self, input: ::std::option::Option<f64>) -> Self {
        self.begin_audio_time = input;
        self
    }
    /// <p>The start time, in milliseconds, of the segment.</p>
    pub fn get_begin_audio_time(&self) -> &::std::option::Option<f64> {
        &self.begin_audio_time
    }
    /// <p>The end time, in milliseconds, of the segment.</p>
    pub fn end_audio_time(mut self, input: f64) -> Self {
        self.end_audio_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time, in milliseconds, of the segment.</p>
    pub fn set_end_audio_time(mut self, input: ::std::option::Option<f64>) -> Self {
        self.end_audio_time = input;
        self
    }
    /// <p>The end time, in milliseconds, of the segment.</p>
    pub fn get_end_audio_time(&self) -> &::std::option::Option<f64> {
        &self.end_audio_time
    }
    /// <p>Contains transcribed text of the segment.</p>
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains transcribed text of the segment.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>Contains transcribed text of the segment.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>Contains words, phrases, or punctuation marks in your segment.</p>
    pub fn items(mut self, input: crate::types::MedicalScribeTranscriptItem) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains words, phrases, or punctuation marks in your segment.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MedicalScribeTranscriptItem>>) -> Self {
        self.items = input;
        self
    }
    /// <p>Contains words, phrases, or punctuation marks in your segment.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MedicalScribeTranscriptItem>> {
        &self.items
    }
    /// <p>Indicates if the segment is complete.</p>
    /// <p>If <code>IsPartial</code> is <code>true</code>, the segment is not complete. If <code>IsPartial</code> is <code>false</code>, the segment is complete.</p>
    pub fn is_partial(mut self, input: bool) -> Self {
        self.is_partial = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the segment is complete.</p>
    /// <p>If <code>IsPartial</code> is <code>true</code>, the segment is not complete. If <code>IsPartial</code> is <code>false</code>, the segment is complete.</p>
    pub fn set_is_partial(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_partial = input;
        self
    }
    /// <p>Indicates if the segment is complete.</p>
    /// <p>If <code>IsPartial</code> is <code>true</code>, the segment is not complete. If <code>IsPartial</code> is <code>false</code>, the segment is complete.</p>
    pub fn get_is_partial(&self) -> &::std::option::Option<bool> {
        &self.is_partial
    }
    /// <p>Indicates which audio channel is associated with the <code>MedicalScribeTranscriptSegment</code>.</p>
    /// <p>If <code>MedicalScribeChannelDefinition</code> is not provided in the <code>MedicalScribeConfigurationEvent</code>, then this field will not be included.</p>
    pub fn channel_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates which audio channel is associated with the <code>MedicalScribeTranscriptSegment</code>.</p>
    /// <p>If <code>MedicalScribeChannelDefinition</code> is not provided in the <code>MedicalScribeConfigurationEvent</code>, then this field will not be included.</p>
    pub fn set_channel_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_id = input;
        self
    }
    /// <p>Indicates which audio channel is associated with the <code>MedicalScribeTranscriptSegment</code>.</p>
    /// <p>If <code>MedicalScribeChannelDefinition</code> is not provided in the <code>MedicalScribeConfigurationEvent</code>, then this field will not be included.</p>
    pub fn get_channel_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_id
    }
    /// Consumes the builder and constructs a [`MedicalScribeTranscriptSegment`](crate::types::MedicalScribeTranscriptSegment).
    pub fn build(self) -> crate::types::MedicalScribeTranscriptSegment {
        crate::types::MedicalScribeTranscriptSegment {
            segment_id: self.segment_id,
            begin_audio_time: self.begin_audio_time.unwrap_or_default(),
            end_audio_time: self.end_audio_time.unwrap_or_default(),
            content: self.content,
            items: self.items,
            is_partial: self.is_partial.unwrap_or_default(),
            channel_id: self.channel_id,
        }
    }
}
