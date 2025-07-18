// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>ActivityTaskFailed</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivityTaskFailedEventAttributes {
    /// <p>The reason provided for the failure.</p>
    pub reason: ::std::option::Option<::std::string::String>,
    /// <p>The details of the failure.</p>
    pub details: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub scheduled_event_id: i64,
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub started_event_id: i64,
}
impl ActivityTaskFailedEventAttributes {
    /// <p>The reason provided for the failure.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
    /// <p>The details of the failure.</p>
    pub fn details(&self) -> ::std::option::Option<&str> {
        self.details.as_deref()
    }
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn scheduled_event_id(&self) -> i64 {
        self.scheduled_event_id
    }
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn started_event_id(&self) -> i64 {
        self.started_event_id
    }
}
impl ActivityTaskFailedEventAttributes {
    /// Creates a new builder-style object to manufacture [`ActivityTaskFailedEventAttributes`](crate::types::ActivityTaskFailedEventAttributes).
    pub fn builder() -> crate::types::builders::ActivityTaskFailedEventAttributesBuilder {
        crate::types::builders::ActivityTaskFailedEventAttributesBuilder::default()
    }
}

/// A builder for [`ActivityTaskFailedEventAttributes`](crate::types::ActivityTaskFailedEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivityTaskFailedEventAttributesBuilder {
    pub(crate) reason: ::std::option::Option<::std::string::String>,
    pub(crate) details: ::std::option::Option<::std::string::String>,
    pub(crate) scheduled_event_id: ::std::option::Option<i64>,
    pub(crate) started_event_id: ::std::option::Option<i64>,
}
impl ActivityTaskFailedEventAttributesBuilder {
    /// <p>The reason provided for the failure.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason provided for the failure.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason provided for the failure.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// <p>The details of the failure.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details of the failure.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>The details of the failure.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.details
    }
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn scheduled_event_id(mut self, input: i64) -> Self {
        self.scheduled_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_scheduled_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.scheduled_event_id = input;
        self
    }
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_scheduled_event_id(&self) -> &::std::option::Option<i64> {
        &self.scheduled_event_id
    }
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    /// This field is required.
    pub fn started_event_id(mut self, input: i64) -> Self {
        self.started_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_started_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.started_event_id = input;
        self
    }
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_started_event_id(&self) -> &::std::option::Option<i64> {
        &self.started_event_id
    }
    /// Consumes the builder and constructs a [`ActivityTaskFailedEventAttributes`](crate::types::ActivityTaskFailedEventAttributes).
    pub fn build(self) -> crate::types::ActivityTaskFailedEventAttributes {
        crate::types::ActivityTaskFailedEventAttributes {
            reason: self.reason,
            details: self.details,
            scheduled_event_id: self.scheduled_event_id.unwrap_or_default(),
            started_event_id: self.started_event_id.unwrap_or_default(),
        }
    }
}
