// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Event that Amazon Lex V2 sends to indicate that the stream is still open between the client application and Amazon Lex V2</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HeartbeatEvent {
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub event_id: ::std::option::Option<::std::string::String>,
}
impl HeartbeatEvent {
    /// <p>A unique identifier of the event sent by Amazon Lex V2. The identifier is in the form <code>RESPONSE-N</code>, where N is a number starting with one and incremented for each event sent by Amazon Lex V2 in the current session.</p>
    pub fn event_id(&self) -> ::std::option::Option<&str> {
        self.event_id.as_deref()
    }
}
impl HeartbeatEvent {
    /// Creates a new builder-style object to manufacture [`HeartbeatEvent`](crate::types::HeartbeatEvent).
    pub fn builder() -> crate::types::builders::HeartbeatEventBuilder {
        crate::types::builders::HeartbeatEventBuilder::default()
    }
}

/// A builder for [`HeartbeatEvent`](crate::types::HeartbeatEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HeartbeatEventBuilder {
    pub(crate) event_id: ::std::option::Option<::std::string::String>,
}
impl HeartbeatEventBuilder {
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
    /// Consumes the builder and constructs a [`HeartbeatEvent`](crate::types::HeartbeatEvent).
    pub fn build(self) -> crate::types::HeartbeatEvent {
        crate::types::HeartbeatEvent { event_id: self.event_id }
    }
}
