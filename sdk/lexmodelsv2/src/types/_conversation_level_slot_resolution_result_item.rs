// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The slots used for the slot resolution in the conversation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConversationLevelSlotResolutionResultItem {
    /// <p>The intents used in the slots list for the slot resolution details.</p>
    pub intent_name: ::std::string::String,
    /// <p>The slot name in the slots list for the slot resolution details.</p>
    pub slot_name: ::std::string::String,
    /// <p>The number of matching slots used in the slots listings for the slot resolution evaluation.</p>
    pub match_result: crate::types::TestResultMatchStatus,
}
impl ConversationLevelSlotResolutionResultItem {
    /// <p>The intents used in the slots list for the slot resolution details.</p>
    pub fn intent_name(&self) -> &str {
        use std::ops::Deref;
        self.intent_name.deref()
    }
    /// <p>The slot name in the slots list for the slot resolution details.</p>
    pub fn slot_name(&self) -> &str {
        use std::ops::Deref;
        self.slot_name.deref()
    }
    /// <p>The number of matching slots used in the slots listings for the slot resolution evaluation.</p>
    pub fn match_result(&self) -> &crate::types::TestResultMatchStatus {
        &self.match_result
    }
}
impl ConversationLevelSlotResolutionResultItem {
    /// Creates a new builder-style object to manufacture [`ConversationLevelSlotResolutionResultItem`](crate::types::ConversationLevelSlotResolutionResultItem).
    pub fn builder() -> crate::types::builders::ConversationLevelSlotResolutionResultItemBuilder {
        crate::types::builders::ConversationLevelSlotResolutionResultItemBuilder::default()
    }
}

/// A builder for [`ConversationLevelSlotResolutionResultItem`](crate::types::ConversationLevelSlotResolutionResultItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConversationLevelSlotResolutionResultItemBuilder {
    pub(crate) intent_name: ::std::option::Option<::std::string::String>,
    pub(crate) slot_name: ::std::option::Option<::std::string::String>,
    pub(crate) match_result: ::std::option::Option<crate::types::TestResultMatchStatus>,
}
impl ConversationLevelSlotResolutionResultItemBuilder {
    /// <p>The intents used in the slots list for the slot resolution details.</p>
    /// This field is required.
    pub fn intent_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intent_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The intents used in the slots list for the slot resolution details.</p>
    pub fn set_intent_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intent_name = input;
        self
    }
    /// <p>The intents used in the slots list for the slot resolution details.</p>
    pub fn get_intent_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.intent_name
    }
    /// <p>The slot name in the slots list for the slot resolution details.</p>
    /// This field is required.
    pub fn slot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.slot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The slot name in the slots list for the slot resolution details.</p>
    pub fn set_slot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.slot_name = input;
        self
    }
    /// <p>The slot name in the slots list for the slot resolution details.</p>
    pub fn get_slot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.slot_name
    }
    /// <p>The number of matching slots used in the slots listings for the slot resolution evaluation.</p>
    /// This field is required.
    pub fn match_result(mut self, input: crate::types::TestResultMatchStatus) -> Self {
        self.match_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of matching slots used in the slots listings for the slot resolution evaluation.</p>
    pub fn set_match_result(mut self, input: ::std::option::Option<crate::types::TestResultMatchStatus>) -> Self {
        self.match_result = input;
        self
    }
    /// <p>The number of matching slots used in the slots listings for the slot resolution evaluation.</p>
    pub fn get_match_result(&self) -> &::std::option::Option<crate::types::TestResultMatchStatus> {
        &self.match_result
    }
    /// Consumes the builder and constructs a [`ConversationLevelSlotResolutionResultItem`](crate::types::ConversationLevelSlotResolutionResultItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`intent_name`](crate::types::builders::ConversationLevelSlotResolutionResultItemBuilder::intent_name)
    /// - [`slot_name`](crate::types::builders::ConversationLevelSlotResolutionResultItemBuilder::slot_name)
    /// - [`match_result`](crate::types::builders::ConversationLevelSlotResolutionResultItemBuilder::match_result)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ConversationLevelSlotResolutionResultItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConversationLevelSlotResolutionResultItem {
            intent_name: self.intent_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "intent_name",
                    "intent_name was not specified but it is required when building ConversationLevelSlotResolutionResultItem",
                )
            })?,
            slot_name: self.slot_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "slot_name",
                    "slot_name was not specified but it is required when building ConversationLevelSlotResolutionResultItem",
                )
            })?,
            match_result: self.match_result.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "match_result",
                    "match_result was not specified but it is required when building ConversationLevelSlotResolutionResultItem",
                )
            })?,
        })
    }
}
