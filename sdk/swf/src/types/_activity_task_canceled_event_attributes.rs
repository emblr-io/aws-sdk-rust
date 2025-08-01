// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>ActivityTaskCanceled</code> event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivityTaskCanceledEventAttributes {
    /// <p>Details of the cancellation.</p>
    pub details: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the <code>ActivityTaskScheduled</code> event that was recorded when this activity task was scheduled. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub scheduled_event_id: i64,
    /// <p>The ID of the <code>ActivityTaskStarted</code> event recorded when this activity task was started. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub started_event_id: i64,
    /// <p>If set, contains the ID of the last <code>ActivityTaskCancelRequested</code> event recorded for this activity task. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub latest_cancel_requested_event_id: i64,
}
impl ActivityTaskCanceledEventAttributes {
    /// <p>Details of the cancellation.</p>
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
    /// <p>If set, contains the ID of the last <code>ActivityTaskCancelRequested</code> event recorded for this activity task. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn latest_cancel_requested_event_id(&self) -> i64 {
        self.latest_cancel_requested_event_id
    }
}
impl ActivityTaskCanceledEventAttributes {
    /// Creates a new builder-style object to manufacture [`ActivityTaskCanceledEventAttributes`](crate::types::ActivityTaskCanceledEventAttributes).
    pub fn builder() -> crate::types::builders::ActivityTaskCanceledEventAttributesBuilder {
        crate::types::builders::ActivityTaskCanceledEventAttributesBuilder::default()
    }
}

/// A builder for [`ActivityTaskCanceledEventAttributes`](crate::types::ActivityTaskCanceledEventAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivityTaskCanceledEventAttributesBuilder {
    pub(crate) details: ::std::option::Option<::std::string::String>,
    pub(crate) scheduled_event_id: ::std::option::Option<i64>,
    pub(crate) started_event_id: ::std::option::Option<i64>,
    pub(crate) latest_cancel_requested_event_id: ::std::option::Option<i64>,
}
impl ActivityTaskCanceledEventAttributesBuilder {
    /// <p>Details of the cancellation.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Details of the cancellation.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>Details of the cancellation.</p>
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
    /// <p>If set, contains the ID of the last <code>ActivityTaskCancelRequested</code> event recorded for this activity task. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn latest_cancel_requested_event_id(mut self, input: i64) -> Self {
        self.latest_cancel_requested_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set, contains the ID of the last <code>ActivityTaskCancelRequested</code> event recorded for this activity task. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn set_latest_cancel_requested_event_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.latest_cancel_requested_event_id = input;
        self
    }
    /// <p>If set, contains the ID of the last <code>ActivityTaskCancelRequested</code> event recorded for this activity task. This information can be useful for diagnosing problems by tracing back the chain of events leading up to this event.</p>
    pub fn get_latest_cancel_requested_event_id(&self) -> &::std::option::Option<i64> {
        &self.latest_cancel_requested_event_id
    }
    /// Consumes the builder and constructs a [`ActivityTaskCanceledEventAttributes`](crate::types::ActivityTaskCanceledEventAttributes).
    pub fn build(self) -> crate::types::ActivityTaskCanceledEventAttributes {
        crate::types::ActivityTaskCanceledEventAttributes {
            details: self.details,
            scheduled_event_id: self.scheduled_event_id.unwrap_or_default(),
            started_event_id: self.started_event_id.unwrap_or_default(),
            latest_cancel_requested_event_id: self.latest_cancel_requested_event_id.unwrap_or_default(),
        }
    }
}
