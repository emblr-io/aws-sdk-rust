// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Event sent from the client application to Amazon Lex V2 to indicate that playback of audio is complete and that Amazon Lex V2 should start processing the user's input.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PlaybackCompletionEvent {
    /// <p>A unique identifier that your application assigns to the event. You can use this to identify events in logs.</p>
    pub event_id: ::std::option::Option<::std::string::String>,
    /// <p>A timestamp set by the client of the date and time that the event was sent to Amazon Lex V2.</p>
    pub client_timestamp_millis: i64,
}
impl PlaybackCompletionEvent {
    /// <p>A unique identifier that your application assigns to the event. You can use this to identify events in logs.</p>
    pub fn event_id(&self) -> ::std::option::Option<&str> {
        self.event_id.as_deref()
    }
    /// <p>A timestamp set by the client of the date and time that the event was sent to Amazon Lex V2.</p>
    pub fn client_timestamp_millis(&self) -> i64 {
        self.client_timestamp_millis
    }
}
impl PlaybackCompletionEvent {
    /// Creates a new builder-style object to manufacture [`PlaybackCompletionEvent`](crate::types::PlaybackCompletionEvent).
    pub fn builder() -> crate::types::builders::PlaybackCompletionEventBuilder {
        crate::types::builders::PlaybackCompletionEventBuilder::default()
    }
}

/// A builder for [`PlaybackCompletionEvent`](crate::types::PlaybackCompletionEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PlaybackCompletionEventBuilder {
    pub(crate) event_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_timestamp_millis: ::std::option::Option<i64>,
}
impl PlaybackCompletionEventBuilder {
    /// <p>A unique identifier that your application assigns to the event. You can use this to identify events in logs.</p>
    pub fn event_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier that your application assigns to the event. You can use this to identify events in logs.</p>
    pub fn set_event_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_id = input;
        self
    }
    /// <p>A unique identifier that your application assigns to the event. You can use this to identify events in logs.</p>
    pub fn get_event_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_id
    }
    /// <p>A timestamp set by the client of the date and time that the event was sent to Amazon Lex V2.</p>
    pub fn client_timestamp_millis(mut self, input: i64) -> Self {
        self.client_timestamp_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp set by the client of the date and time that the event was sent to Amazon Lex V2.</p>
    pub fn set_client_timestamp_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.client_timestamp_millis = input;
        self
    }
    /// <p>A timestamp set by the client of the date and time that the event was sent to Amazon Lex V2.</p>
    pub fn get_client_timestamp_millis(&self) -> &::std::option::Option<i64> {
        &self.client_timestamp_millis
    }
    /// Consumes the builder and constructs a [`PlaybackCompletionEvent`](crate::types::PlaybackCompletionEvent).
    pub fn build(self) -> crate::types::PlaybackCompletionEvent {
        crate::types::PlaybackCompletionEvent {
            event_id: self.event_id,
            client_timestamp_millis: self.client_timestamp_millis.unwrap_or_default(),
        }
    }
}
