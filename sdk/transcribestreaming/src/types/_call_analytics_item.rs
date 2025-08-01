// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A word, phrase, or punctuation mark in your Call Analytics transcription output, along with various associated attributes, such as confidence score, type, and start and end times.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CallAnalyticsItem {
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the start of the identified item.</p>
    pub begin_offset_millis: ::std::option::Option<i64>,
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the end of the identified item.</p>
    pub end_offset_millis: ::std::option::Option<i64>,
    /// <p>The type of item identified. Options are: <code>PRONUNCIATION</code> (spoken words) and <code>PUNCTUATION</code>.</p>
    pub r#type: ::std::option::Option<crate::types::ItemType>,
    /// <p>The word or punctuation that was transcribed.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>The confidence score associated with a word or phrase in your transcript.</p>
    /// <p>Confidence scores are values between 0 and 1. A larger value indicates a higher probability that the identified item correctly matches the item spoken in your media.</p>
    pub confidence: ::std::option::Option<f64>,
    /// <p>Indicates whether the specified item matches a word in the vocabulary filter included in your Call Analytics request. If <code>true</code>, there is a vocabulary filter match.</p>
    pub vocabulary_filter_match: bool,
    /// <p>If partial result stabilization is enabled, <code>Stable</code> indicates whether the specified item is stable (<code>true</code>) or if it may change when the segment is complete (<code>false</code>).</p>
    pub stable: ::std::option::Option<bool>,
}
impl CallAnalyticsItem {
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the start of the identified item.</p>
    pub fn begin_offset_millis(&self) -> ::std::option::Option<i64> {
        self.begin_offset_millis
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the end of the identified item.</p>
    pub fn end_offset_millis(&self) -> ::std::option::Option<i64> {
        self.end_offset_millis
    }
    /// <p>The type of item identified. Options are: <code>PRONUNCIATION</code> (spoken words) and <code>PUNCTUATION</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ItemType> {
        self.r#type.as_ref()
    }
    /// <p>The word or punctuation that was transcribed.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>The confidence score associated with a word or phrase in your transcript.</p>
    /// <p>Confidence scores are values between 0 and 1. A larger value indicates a higher probability that the identified item correctly matches the item spoken in your media.</p>
    pub fn confidence(&self) -> ::std::option::Option<f64> {
        self.confidence
    }
    /// <p>Indicates whether the specified item matches a word in the vocabulary filter included in your Call Analytics request. If <code>true</code>, there is a vocabulary filter match.</p>
    pub fn vocabulary_filter_match(&self) -> bool {
        self.vocabulary_filter_match
    }
    /// <p>If partial result stabilization is enabled, <code>Stable</code> indicates whether the specified item is stable (<code>true</code>) or if it may change when the segment is complete (<code>false</code>).</p>
    pub fn stable(&self) -> ::std::option::Option<bool> {
        self.stable
    }
}
impl CallAnalyticsItem {
    /// Creates a new builder-style object to manufacture [`CallAnalyticsItem`](crate::types::CallAnalyticsItem).
    pub fn builder() -> crate::types::builders::CallAnalyticsItemBuilder {
        crate::types::builders::CallAnalyticsItemBuilder::default()
    }
}

/// A builder for [`CallAnalyticsItem`](crate::types::CallAnalyticsItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CallAnalyticsItemBuilder {
    pub(crate) begin_offset_millis: ::std::option::Option<i64>,
    pub(crate) end_offset_millis: ::std::option::Option<i64>,
    pub(crate) r#type: ::std::option::Option<crate::types::ItemType>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) confidence: ::std::option::Option<f64>,
    pub(crate) vocabulary_filter_match: ::std::option::Option<bool>,
    pub(crate) stable: ::std::option::Option<bool>,
}
impl CallAnalyticsItemBuilder {
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the start of the identified item.</p>
    pub fn begin_offset_millis(mut self, input: i64) -> Self {
        self.begin_offset_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the start of the identified item.</p>
    pub fn set_begin_offset_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.begin_offset_millis = input;
        self
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the start of the identified item.</p>
    pub fn get_begin_offset_millis(&self) -> &::std::option::Option<i64> {
        &self.begin_offset_millis
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the end of the identified item.</p>
    pub fn end_offset_millis(mut self, input: i64) -> Self {
        self.end_offset_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the end of the identified item.</p>
    pub fn set_end_offset_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.end_offset_millis = input;
        self
    }
    /// <p>The time, in milliseconds, from the beginning of the audio stream to the end of the identified item.</p>
    pub fn get_end_offset_millis(&self) -> &::std::option::Option<i64> {
        &self.end_offset_millis
    }
    /// <p>The type of item identified. Options are: <code>PRONUNCIATION</code> (spoken words) and <code>PUNCTUATION</code>.</p>
    pub fn r#type(mut self, input: crate::types::ItemType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of item identified. Options are: <code>PRONUNCIATION</code> (spoken words) and <code>PUNCTUATION</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ItemType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of item identified. Options are: <code>PRONUNCIATION</code> (spoken words) and <code>PUNCTUATION</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ItemType> {
        &self.r#type
    }
    /// <p>The word or punctuation that was transcribed.</p>
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The word or punctuation that was transcribed.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The word or punctuation that was transcribed.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// <p>The confidence score associated with a word or phrase in your transcript.</p>
    /// <p>Confidence scores are values between 0 and 1. A larger value indicates a higher probability that the identified item correctly matches the item spoken in your media.</p>
    pub fn confidence(mut self, input: f64) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The confidence score associated with a word or phrase in your transcript.</p>
    /// <p>Confidence scores are values between 0 and 1. A larger value indicates a higher probability that the identified item correctly matches the item spoken in your media.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<f64>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>The confidence score associated with a word or phrase in your transcript.</p>
    /// <p>Confidence scores are values between 0 and 1. A larger value indicates a higher probability that the identified item correctly matches the item spoken in your media.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<f64> {
        &self.confidence
    }
    /// <p>Indicates whether the specified item matches a word in the vocabulary filter included in your Call Analytics request. If <code>true</code>, there is a vocabulary filter match.</p>
    pub fn vocabulary_filter_match(mut self, input: bool) -> Self {
        self.vocabulary_filter_match = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the specified item matches a word in the vocabulary filter included in your Call Analytics request. If <code>true</code>, there is a vocabulary filter match.</p>
    pub fn set_vocabulary_filter_match(mut self, input: ::std::option::Option<bool>) -> Self {
        self.vocabulary_filter_match = input;
        self
    }
    /// <p>Indicates whether the specified item matches a word in the vocabulary filter included in your Call Analytics request. If <code>true</code>, there is a vocabulary filter match.</p>
    pub fn get_vocabulary_filter_match(&self) -> &::std::option::Option<bool> {
        &self.vocabulary_filter_match
    }
    /// <p>If partial result stabilization is enabled, <code>Stable</code> indicates whether the specified item is stable (<code>true</code>) or if it may change when the segment is complete (<code>false</code>).</p>
    pub fn stable(mut self, input: bool) -> Self {
        self.stable = ::std::option::Option::Some(input);
        self
    }
    /// <p>If partial result stabilization is enabled, <code>Stable</code> indicates whether the specified item is stable (<code>true</code>) or if it may change when the segment is complete (<code>false</code>).</p>
    pub fn set_stable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.stable = input;
        self
    }
    /// <p>If partial result stabilization is enabled, <code>Stable</code> indicates whether the specified item is stable (<code>true</code>) or if it may change when the segment is complete (<code>false</code>).</p>
    pub fn get_stable(&self) -> &::std::option::Option<bool> {
        &self.stable
    }
    /// Consumes the builder and constructs a [`CallAnalyticsItem`](crate::types::CallAnalyticsItem).
    pub fn build(self) -> crate::types::CallAnalyticsItem {
        crate::types::CallAnalyticsItem {
            begin_offset_millis: self.begin_offset_millis,
            end_offset_millis: self.end_offset_millis,
            r#type: self.r#type,
            content: self.content,
            confidence: self.confidence,
            vocabulary_filter_match: self.vocabulary_filter_match.unwrap_or_default(),
            stable: self.stable,
        }
    }
}
