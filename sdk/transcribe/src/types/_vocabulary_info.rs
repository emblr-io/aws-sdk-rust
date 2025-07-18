// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a custom vocabulary, including the language of the custom vocabulary, when it was last modified, its name, and the processing state.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VocabularyInfo {
    /// <p>A unique name, chosen by you, for your custom vocabulary. This name is case sensitive, cannot contain spaces, and must be unique within an Amazon Web Services account.</p>
    pub vocabulary_name: ::std::option::Option<::std::string::String>,
    /// <p>The language code used to create your custom vocabulary. Each custom vocabulary must contain terms in only one language.</p>
    /// <p>A custom vocabulary can only be used to transcribe files in the same language as the custom vocabulary. For example, if you create a custom vocabulary using US English (<code>en-US</code>), you can only apply this custom vocabulary to files that contain English audio.</p>
    pub language_code: ::std::option::Option<crate::types::LanguageCode>,
    /// <p>The date and time the specified custom vocabulary was last modified.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The processing state of your custom vocabulary. If the state is <code>READY</code>, you can use the custom vocabulary in a <code>StartTranscriptionJob</code> request.</p>
    pub vocabulary_state: ::std::option::Option<crate::types::VocabularyState>,
}
impl VocabularyInfo {
    /// <p>A unique name, chosen by you, for your custom vocabulary. This name is case sensitive, cannot contain spaces, and must be unique within an Amazon Web Services account.</p>
    pub fn vocabulary_name(&self) -> ::std::option::Option<&str> {
        self.vocabulary_name.as_deref()
    }
    /// <p>The language code used to create your custom vocabulary. Each custom vocabulary must contain terms in only one language.</p>
    /// <p>A custom vocabulary can only be used to transcribe files in the same language as the custom vocabulary. For example, if you create a custom vocabulary using US English (<code>en-US</code>), you can only apply this custom vocabulary to files that contain English audio.</p>
    pub fn language_code(&self) -> ::std::option::Option<&crate::types::LanguageCode> {
        self.language_code.as_ref()
    }
    /// <p>The date and time the specified custom vocabulary was last modified.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The processing state of your custom vocabulary. If the state is <code>READY</code>, you can use the custom vocabulary in a <code>StartTranscriptionJob</code> request.</p>
    pub fn vocabulary_state(&self) -> ::std::option::Option<&crate::types::VocabularyState> {
        self.vocabulary_state.as_ref()
    }
}
impl VocabularyInfo {
    /// Creates a new builder-style object to manufacture [`VocabularyInfo`](crate::types::VocabularyInfo).
    pub fn builder() -> crate::types::builders::VocabularyInfoBuilder {
        crate::types::builders::VocabularyInfoBuilder::default()
    }
}

/// A builder for [`VocabularyInfo`](crate::types::VocabularyInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VocabularyInfoBuilder {
    pub(crate) vocabulary_name: ::std::option::Option<::std::string::String>,
    pub(crate) language_code: ::std::option::Option<crate::types::LanguageCode>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) vocabulary_state: ::std::option::Option<crate::types::VocabularyState>,
}
impl VocabularyInfoBuilder {
    /// <p>A unique name, chosen by you, for your custom vocabulary. This name is case sensitive, cannot contain spaces, and must be unique within an Amazon Web Services account.</p>
    pub fn vocabulary_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vocabulary_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique name, chosen by you, for your custom vocabulary. This name is case sensitive, cannot contain spaces, and must be unique within an Amazon Web Services account.</p>
    pub fn set_vocabulary_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vocabulary_name = input;
        self
    }
    /// <p>A unique name, chosen by you, for your custom vocabulary. This name is case sensitive, cannot contain spaces, and must be unique within an Amazon Web Services account.</p>
    pub fn get_vocabulary_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vocabulary_name
    }
    /// <p>The language code used to create your custom vocabulary. Each custom vocabulary must contain terms in only one language.</p>
    /// <p>A custom vocabulary can only be used to transcribe files in the same language as the custom vocabulary. For example, if you create a custom vocabulary using US English (<code>en-US</code>), you can only apply this custom vocabulary to files that contain English audio.</p>
    pub fn language_code(mut self, input: crate::types::LanguageCode) -> Self {
        self.language_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The language code used to create your custom vocabulary. Each custom vocabulary must contain terms in only one language.</p>
    /// <p>A custom vocabulary can only be used to transcribe files in the same language as the custom vocabulary. For example, if you create a custom vocabulary using US English (<code>en-US</code>), you can only apply this custom vocabulary to files that contain English audio.</p>
    pub fn set_language_code(mut self, input: ::std::option::Option<crate::types::LanguageCode>) -> Self {
        self.language_code = input;
        self
    }
    /// <p>The language code used to create your custom vocabulary. Each custom vocabulary must contain terms in only one language.</p>
    /// <p>A custom vocabulary can only be used to transcribe files in the same language as the custom vocabulary. For example, if you create a custom vocabulary using US English (<code>en-US</code>), you can only apply this custom vocabulary to files that contain English audio.</p>
    pub fn get_language_code(&self) -> &::std::option::Option<crate::types::LanguageCode> {
        &self.language_code
    }
    /// <p>The date and time the specified custom vocabulary was last modified.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the specified custom vocabulary was last modified.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The date and time the specified custom vocabulary was last modified.</p>
    /// <p>Timestamps are in the format <code>YYYY-MM-DD'T'HH:MM:SS.SSSSSS-UTC</code>. For example, <code>2022-05-04T12:32:58.761000-07:00</code> represents 12:32 PM UTC-7 on May 4, 2022.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The processing state of your custom vocabulary. If the state is <code>READY</code>, you can use the custom vocabulary in a <code>StartTranscriptionJob</code> request.</p>
    pub fn vocabulary_state(mut self, input: crate::types::VocabularyState) -> Self {
        self.vocabulary_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The processing state of your custom vocabulary. If the state is <code>READY</code>, you can use the custom vocabulary in a <code>StartTranscriptionJob</code> request.</p>
    pub fn set_vocabulary_state(mut self, input: ::std::option::Option<crate::types::VocabularyState>) -> Self {
        self.vocabulary_state = input;
        self
    }
    /// <p>The processing state of your custom vocabulary. If the state is <code>READY</code>, you can use the custom vocabulary in a <code>StartTranscriptionJob</code> request.</p>
    pub fn get_vocabulary_state(&self) -> &::std::option::Option<crate::types::VocabularyState> {
        &self.vocabulary_state
    }
    /// Consumes the builder and constructs a [`VocabularyInfo`](crate::types::VocabularyInfo).
    pub fn build(self) -> crate::types::VocabularyInfo {
        crate::types::VocabularyInfo {
            vocabulary_name: self.vocabulary_name,
            language_code: self.language_code,
            last_modified_time: self.last_modified_time,
            vocabulary_state: self.vocabulary_state,
        }
    }
}
