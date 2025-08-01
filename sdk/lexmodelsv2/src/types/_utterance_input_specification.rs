// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about input of an utterance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UtteranceInputSpecification {
    /// <p>A text input transcription of the utterance. It is only applicable for test-sets containing text data.</p>
    pub text_input: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the audio input for an utterance.</p>
    pub audio_input: ::std::option::Option<crate::types::UtteranceAudioInputSpecification>,
}
impl UtteranceInputSpecification {
    /// <p>A text input transcription of the utterance. It is only applicable for test-sets containing text data.</p>
    pub fn text_input(&self) -> ::std::option::Option<&str> {
        self.text_input.as_deref()
    }
    /// <p>Contains information about the audio input for an utterance.</p>
    pub fn audio_input(&self) -> ::std::option::Option<&crate::types::UtteranceAudioInputSpecification> {
        self.audio_input.as_ref()
    }
}
impl UtteranceInputSpecification {
    /// Creates a new builder-style object to manufacture [`UtteranceInputSpecification`](crate::types::UtteranceInputSpecification).
    pub fn builder() -> crate::types::builders::UtteranceInputSpecificationBuilder {
        crate::types::builders::UtteranceInputSpecificationBuilder::default()
    }
}

/// A builder for [`UtteranceInputSpecification`](crate::types::UtteranceInputSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UtteranceInputSpecificationBuilder {
    pub(crate) text_input: ::std::option::Option<::std::string::String>,
    pub(crate) audio_input: ::std::option::Option<crate::types::UtteranceAudioInputSpecification>,
}
impl UtteranceInputSpecificationBuilder {
    /// <p>A text input transcription of the utterance. It is only applicable for test-sets containing text data.</p>
    pub fn text_input(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text_input = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A text input transcription of the utterance. It is only applicable for test-sets containing text data.</p>
    pub fn set_text_input(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text_input = input;
        self
    }
    /// <p>A text input transcription of the utterance. It is only applicable for test-sets containing text data.</p>
    pub fn get_text_input(&self) -> &::std::option::Option<::std::string::String> {
        &self.text_input
    }
    /// <p>Contains information about the audio input for an utterance.</p>
    pub fn audio_input(mut self, input: crate::types::UtteranceAudioInputSpecification) -> Self {
        self.audio_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the audio input for an utterance.</p>
    pub fn set_audio_input(mut self, input: ::std::option::Option<crate::types::UtteranceAudioInputSpecification>) -> Self {
        self.audio_input = input;
        self
    }
    /// <p>Contains information about the audio input for an utterance.</p>
    pub fn get_audio_input(&self) -> &::std::option::Option<crate::types::UtteranceAudioInputSpecification> {
        &self.audio_input
    }
    /// Consumes the builder and constructs a [`UtteranceInputSpecification`](crate::types::UtteranceInputSpecification).
    pub fn build(self) -> crate::types::UtteranceInputSpecification {
        crate::types::UtteranceInputSpecification {
            text_input: self.text_input,
            audio_input: self.audio_input,
        }
    }
}
