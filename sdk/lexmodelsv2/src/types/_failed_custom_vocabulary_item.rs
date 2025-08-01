// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The unique failed custom vocabulary item from the custom vocabulary list.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FailedCustomVocabularyItem {
    /// <p>The unique item identifer for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub item_id: ::std::option::Option<::std::string::String>,
    /// <p>The error message for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The unique error code for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
}
impl FailedCustomVocabularyItem {
    /// <p>The unique item identifer for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn item_id(&self) -> ::std::option::Option<&str> {
        self.item_id.as_deref()
    }
    /// <p>The error message for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The unique error code for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.error_code.as_ref()
    }
}
impl FailedCustomVocabularyItem {
    /// Creates a new builder-style object to manufacture [`FailedCustomVocabularyItem`](crate::types::FailedCustomVocabularyItem).
    pub fn builder() -> crate::types::builders::FailedCustomVocabularyItemBuilder {
        crate::types::builders::FailedCustomVocabularyItemBuilder::default()
    }
}

/// A builder for [`FailedCustomVocabularyItem`](crate::types::FailedCustomVocabularyItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FailedCustomVocabularyItemBuilder {
    pub(crate) item_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
}
impl FailedCustomVocabularyItemBuilder {
    /// <p>The unique item identifer for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique item identifer for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn set_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.item_id = input;
        self
    }
    /// <p>The unique item identifer for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn get_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.item_id
    }
    /// <p>The error message for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>The unique error code for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unique error code for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The unique error code for the failed custom vocabulary item from the custom vocabulary list.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// Consumes the builder and constructs a [`FailedCustomVocabularyItem`](crate::types::FailedCustomVocabularyItem).
    pub fn build(self) -> crate::types::FailedCustomVocabularyItem {
        crate::types::FailedCustomVocabularyItem {
            item_id: self.item_id,
            error_message: self.error_message,
            error_code: self.error_code,
        }
    }
}
