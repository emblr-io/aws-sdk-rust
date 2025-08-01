// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Event sent from Amazon Lex V2 to your client application that contains a transcript of voice audio.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TranscriptEvent {
    /// <p>The transcript of the voice audio from the user.</p>
    pub transcript: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub event_id: ::std::option::Option<::std::string::String>,
}
impl TranscriptEvent {
    /// <p>The transcript of the voice audio from the user.</p>
    pub fn transcript(&self) -> ::std::option::Option<&str> {
        self.transcript.as_deref()
    }
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub fn event_id(&self) -> ::std::option::Option<&str> {
        self.event_id.as_deref()
    }
}
impl TranscriptEvent {
    /// Creates a new builder-style object to manufacture [`TranscriptEvent`](crate::types::TranscriptEvent).
    pub fn builder() -> crate::types::builders::TranscriptEventBuilder {
        crate::types::builders::TranscriptEventBuilder::default()
    }
}

/// A builder for [`TranscriptEvent`](crate::types::TranscriptEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TranscriptEventBuilder {
    pub(crate) transcript: ::std::option::Option<::std::string::String>,
    pub(crate) event_id: ::std::option::Option<::std::string::String>,
}
impl TranscriptEventBuilder {
    /// <p>The transcript of the voice audio from the user.</p>
    pub fn transcript(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transcript = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transcript of the voice audio from the user.</p>
    pub fn set_transcript(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transcript = input;
        self
    }
    /// <p>The transcript of the voice audio from the user.</p>
    pub fn get_transcript(&self) -> &::std::option::Option<::std::string::String> {
        &self.transcript
    }
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub fn event_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub fn set_event_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_id = input;
        self
    }
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub fn get_event_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_id
    }
    /// Consumes the builder and constructs a [`TranscriptEvent`](crate::types::TranscriptEvent).
    pub fn build(self) -> crate::types::TranscriptEvent {
        crate::types::TranscriptEvent {
            transcript: self.transcript,
            event_id: self.event_id,
        }
    }
}
