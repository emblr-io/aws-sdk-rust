// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The test result evaluation item at the conversation level.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConversationLevelTestResultItem {
    /// <p>The conversation Id of the test result evaluation item.</p>
    pub conversation_id: ::std::string::String,
    /// <p>The end-to-end success or failure of the test result evaluation item.</p>
    pub end_to_end_result: crate::types::TestResultMatchStatus,
    /// <p>The speech transcription success or failure of the test result evaluation item.</p>
    pub speech_transcription_result: ::std::option::Option<crate::types::TestResultMatchStatus>,
    /// <p>The intent classification of the test result evaluation item.</p>
    pub intent_classification_results: ::std::vec::Vec<crate::types::ConversationLevelIntentClassificationResultItem>,
    /// <p>The slot success or failure of the test result evaluation item.</p>
    pub slot_resolution_results: ::std::vec::Vec<crate::types::ConversationLevelSlotResolutionResultItem>,
}
impl ConversationLevelTestResultItem {
    /// <p>The conversation Id of the test result evaluation item.</p>
    pub fn conversation_id(&self) -> &str {
        use std::ops::Deref;
        self.conversation_id.deref()
    }
    /// <p>The end-to-end success or failure of the test result evaluation item.</p>
    pub fn end_to_end_result(&self) -> &crate::types::TestResultMatchStatus {
        &self.end_to_end_result
    }
    /// <p>The speech transcription success or failure of the test result evaluation item.</p>
    pub fn speech_transcription_result(&self) -> ::std::option::Option<&crate::types::TestResultMatchStatus> {
        self.speech_transcription_result.as_ref()
    }
    /// <p>The intent classification of the test result evaluation item.</p>
    pub fn intent_classification_results(&self) -> &[crate::types::ConversationLevelIntentClassificationResultItem] {
        use std::ops::Deref;
        self.intent_classification_results.deref()
    }
    /// <p>The slot success or failure of the test result evaluation item.</p>
    pub fn slot_resolution_results(&self) -> &[crate::types::ConversationLevelSlotResolutionResultItem] {
        use std::ops::Deref;
        self.slot_resolution_results.deref()
    }
}
impl ConversationLevelTestResultItem {
    /// Creates a new builder-style object to manufacture [`ConversationLevelTestResultItem`](crate::types::ConversationLevelTestResultItem).
    pub fn builder() -> crate::types::builders::ConversationLevelTestResultItemBuilder {
        crate::types::builders::ConversationLevelTestResultItemBuilder::default()
    }
}

/// A builder for [`ConversationLevelTestResultItem`](crate::types::ConversationLevelTestResultItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConversationLevelTestResultItemBuilder {
    pub(crate) conversation_id: ::std::option::Option<::std::string::String>,
    pub(crate) end_to_end_result: ::std::option::Option<crate::types::TestResultMatchStatus>,
    pub(crate) speech_transcription_result: ::std::option::Option<crate::types::TestResultMatchStatus>,
    pub(crate) intent_classification_results: ::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelIntentClassificationResultItem>>,
    pub(crate) slot_resolution_results: ::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelSlotResolutionResultItem>>,
}
impl ConversationLevelTestResultItemBuilder {
    /// <p>The conversation Id of the test result evaluation item.</p>
    /// This field is required.
    pub fn conversation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conversation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The conversation Id of the test result evaluation item.</p>
    pub fn set_conversation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conversation_id = input;
        self
    }
    /// <p>The conversation Id of the test result evaluation item.</p>
    pub fn get_conversation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conversation_id
    }
    /// <p>The end-to-end success or failure of the test result evaluation item.</p>
    /// This field is required.
    pub fn end_to_end_result(mut self, input: crate::types::TestResultMatchStatus) -> Self {
        self.end_to_end_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end-to-end success or failure of the test result evaluation item.</p>
    pub fn set_end_to_end_result(mut self, input: ::std::option::Option<crate::types::TestResultMatchStatus>) -> Self {
        self.end_to_end_result = input;
        self
    }
    /// <p>The end-to-end success or failure of the test result evaluation item.</p>
    pub fn get_end_to_end_result(&self) -> &::std::option::Option<crate::types::TestResultMatchStatus> {
        &self.end_to_end_result
    }
    /// <p>The speech transcription success or failure of the test result evaluation item.</p>
    pub fn speech_transcription_result(mut self, input: crate::types::TestResultMatchStatus) -> Self {
        self.speech_transcription_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The speech transcription success or failure of the test result evaluation item.</p>
    pub fn set_speech_transcription_result(mut self, input: ::std::option::Option<crate::types::TestResultMatchStatus>) -> Self {
        self.speech_transcription_result = input;
        self
    }
    /// <p>The speech transcription success or failure of the test result evaluation item.</p>
    pub fn get_speech_transcription_result(&self) -> &::std::option::Option<crate::types::TestResultMatchStatus> {
        &self.speech_transcription_result
    }
    /// Appends an item to `intent_classification_results`.
    ///
    /// To override the contents of this collection use [`set_intent_classification_results`](Self::set_intent_classification_results).
    ///
    /// <p>The intent classification of the test result evaluation item.</p>
    pub fn intent_classification_results(mut self, input: crate::types::ConversationLevelIntentClassificationResultItem) -> Self {
        let mut v = self.intent_classification_results.unwrap_or_default();
        v.push(input);
        self.intent_classification_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>The intent classification of the test result evaluation item.</p>
    pub fn set_intent_classification_results(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelIntentClassificationResultItem>>,
    ) -> Self {
        self.intent_classification_results = input;
        self
    }
    /// <p>The intent classification of the test result evaluation item.</p>
    pub fn get_intent_classification_results(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelIntentClassificationResultItem>> {
        &self.intent_classification_results
    }
    /// Appends an item to `slot_resolution_results`.
    ///
    /// To override the contents of this collection use [`set_slot_resolution_results`](Self::set_slot_resolution_results).
    ///
    /// <p>The slot success or failure of the test result evaluation item.</p>
    pub fn slot_resolution_results(mut self, input: crate::types::ConversationLevelSlotResolutionResultItem) -> Self {
        let mut v = self.slot_resolution_results.unwrap_or_default();
        v.push(input);
        self.slot_resolution_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>The slot success or failure of the test result evaluation item.</p>
    pub fn set_slot_resolution_results(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelSlotResolutionResultItem>>,
    ) -> Self {
        self.slot_resolution_results = input;
        self
    }
    /// <p>The slot success or failure of the test result evaluation item.</p>
    pub fn get_slot_resolution_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConversationLevelSlotResolutionResultItem>> {
        &self.slot_resolution_results
    }
    /// Consumes the builder and constructs a [`ConversationLevelTestResultItem`](crate::types::ConversationLevelTestResultItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`conversation_id`](crate::types::builders::ConversationLevelTestResultItemBuilder::conversation_id)
    /// - [`end_to_end_result`](crate::types::builders::ConversationLevelTestResultItemBuilder::end_to_end_result)
    /// - [`intent_classification_results`](crate::types::builders::ConversationLevelTestResultItemBuilder::intent_classification_results)
    /// - [`slot_resolution_results`](crate::types::builders::ConversationLevelTestResultItemBuilder::slot_resolution_results)
    pub fn build(self) -> ::std::result::Result<crate::types::ConversationLevelTestResultItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConversationLevelTestResultItem {
            conversation_id: self.conversation_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conversation_id",
                    "conversation_id was not specified but it is required when building ConversationLevelTestResultItem",
                )
            })?,
            end_to_end_result: self.end_to_end_result.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "end_to_end_result",
                    "end_to_end_result was not specified but it is required when building ConversationLevelTestResultItem",
                )
            })?,
            speech_transcription_result: self.speech_transcription_result,
            intent_classification_results: self.intent_classification_results.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "intent_classification_results",
                    "intent_classification_results was not specified but it is required when building ConversationLevelTestResultItem",
                )
            })?,
            slot_resolution_results: self.slot_resolution_results.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "slot_resolution_results",
                    "slot_resolution_results was not specified but it is required when building ConversationLevelTestResultItem",
                )
            })?,
        })
    }
}
