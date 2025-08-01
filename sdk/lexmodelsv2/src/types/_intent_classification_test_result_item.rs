// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information for an intent that is classified by the test workbench.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IntentClassificationTestResultItem {
    /// <p>The name of the intent.</p>
    pub intent_name: ::std::string::String,
    /// <p>Indicates whether the conversation involves multiple turns or not.</p>
    pub multi_turn_conversation: bool,
    /// <p>The result of the intent classification test.</p>
    pub result_counts: ::std::option::Option<crate::types::IntentClassificationTestResultItemCounts>,
}
impl IntentClassificationTestResultItem {
    /// <p>The name of the intent.</p>
    pub fn intent_name(&self) -> &str {
        use std::ops::Deref;
        self.intent_name.deref()
    }
    /// <p>Indicates whether the conversation involves multiple turns or not.</p>
    pub fn multi_turn_conversation(&self) -> bool {
        self.multi_turn_conversation
    }
    /// <p>The result of the intent classification test.</p>
    pub fn result_counts(&self) -> ::std::option::Option<&crate::types::IntentClassificationTestResultItemCounts> {
        self.result_counts.as_ref()
    }
}
impl IntentClassificationTestResultItem {
    /// Creates a new builder-style object to manufacture [`IntentClassificationTestResultItem`](crate::types::IntentClassificationTestResultItem).
    pub fn builder() -> crate::types::builders::IntentClassificationTestResultItemBuilder {
        crate::types::builders::IntentClassificationTestResultItemBuilder::default()
    }
}

/// A builder for [`IntentClassificationTestResultItem`](crate::types::IntentClassificationTestResultItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IntentClassificationTestResultItemBuilder {
    pub(crate) intent_name: ::std::option::Option<::std::string::String>,
    pub(crate) multi_turn_conversation: ::std::option::Option<bool>,
    pub(crate) result_counts: ::std::option::Option<crate::types::IntentClassificationTestResultItemCounts>,
}
impl IntentClassificationTestResultItemBuilder {
    /// <p>The name of the intent.</p>
    /// This field is required.
    pub fn intent_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intent_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the intent.</p>
    pub fn set_intent_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intent_name = input;
        self
    }
    /// <p>The name of the intent.</p>
    pub fn get_intent_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.intent_name
    }
    /// <p>Indicates whether the conversation involves multiple turns or not.</p>
    /// This field is required.
    pub fn multi_turn_conversation(mut self, input: bool) -> Self {
        self.multi_turn_conversation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the conversation involves multiple turns or not.</p>
    pub fn set_multi_turn_conversation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.multi_turn_conversation = input;
        self
    }
    /// <p>Indicates whether the conversation involves multiple turns or not.</p>
    pub fn get_multi_turn_conversation(&self) -> &::std::option::Option<bool> {
        &self.multi_turn_conversation
    }
    /// <p>The result of the intent classification test.</p>
    /// This field is required.
    pub fn result_counts(mut self, input: crate::types::IntentClassificationTestResultItemCounts) -> Self {
        self.result_counts = ::std::option::Option::Some(input);
        self
    }
    /// <p>The result of the intent classification test.</p>
    pub fn set_result_counts(mut self, input: ::std::option::Option<crate::types::IntentClassificationTestResultItemCounts>) -> Self {
        self.result_counts = input;
        self
    }
    /// <p>The result of the intent classification test.</p>
    pub fn get_result_counts(&self) -> &::std::option::Option<crate::types::IntentClassificationTestResultItemCounts> {
        &self.result_counts
    }
    /// Consumes the builder and constructs a [`IntentClassificationTestResultItem`](crate::types::IntentClassificationTestResultItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`intent_name`](crate::types::builders::IntentClassificationTestResultItemBuilder::intent_name)
    pub fn build(self) -> ::std::result::Result<crate::types::IntentClassificationTestResultItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IntentClassificationTestResultItem {
            intent_name: self.intent_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "intent_name",
                    "intent_name was not specified but it is required when building IntentClassificationTestResultItem",
                )
            })?,
            multi_turn_conversation: self.multi_turn_conversation.unwrap_or_default(),
            result_counts: self.result_counts,
        })
    }
}
