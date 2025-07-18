// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Segment type describing a contact event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RealTimeContactAnalysisSegmentEvent {
    /// <p>The identifier of the contact event.</p>
    pub id: ::std::string::String,
    /// <p>The identifier of the participant.</p>
    pub participant_id: ::std::option::Option<::std::string::String>,
    /// <p>The role of the participant. For example, is it a customer, agent, or system.</p>
    pub participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    /// <p>The display name of the participant. Can be redacted.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>Type of the event. For example, <code>application/vnd.amazonaws.connect.event.participant.left</code>.</p>
    pub event_type: ::std::string::String,
    /// <p>Field describing the time of the event. It can have different representations of time.</p>
    pub time: ::std::option::Option<crate::types::RealTimeContactAnalysisTimeData>,
}
impl RealTimeContactAnalysisSegmentEvent {
    /// <p>The identifier of the contact event.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The identifier of the participant.</p>
    pub fn participant_id(&self) -> ::std::option::Option<&str> {
        self.participant_id.as_deref()
    }
    /// <p>The role of the participant. For example, is it a customer, agent, or system.</p>
    pub fn participant_role(&self) -> ::std::option::Option<&crate::types::ParticipantRole> {
        self.participant_role.as_ref()
    }
    /// <p>The display name of the participant. Can be redacted.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>Type of the event. For example, <code>application/vnd.amazonaws.connect.event.participant.left</code>.</p>
    pub fn event_type(&self) -> &str {
        use std::ops::Deref;
        self.event_type.deref()
    }
    /// <p>Field describing the time of the event. It can have different representations of time.</p>
    pub fn time(&self) -> ::std::option::Option<&crate::types::RealTimeContactAnalysisTimeData> {
        self.time.as_ref()
    }
}
impl RealTimeContactAnalysisSegmentEvent {
    /// Creates a new builder-style object to manufacture [`RealTimeContactAnalysisSegmentEvent`](crate::types::RealTimeContactAnalysisSegmentEvent).
    pub fn builder() -> crate::types::builders::RealTimeContactAnalysisSegmentEventBuilder {
        crate::types::builders::RealTimeContactAnalysisSegmentEventBuilder::default()
    }
}

/// A builder for [`RealTimeContactAnalysisSegmentEvent`](crate::types::RealTimeContactAnalysisSegmentEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RealTimeContactAnalysisSegmentEventBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) participant_id: ::std::option::Option<::std::string::String>,
    pub(crate) participant_role: ::std::option::Option<crate::types::ParticipantRole>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_type: ::std::option::Option<::std::string::String>,
    pub(crate) time: ::std::option::Option<crate::types::RealTimeContactAnalysisTimeData>,
}
impl RealTimeContactAnalysisSegmentEventBuilder {
    /// <p>The identifier of the contact event.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the contact event.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the contact event.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The identifier of the participant.</p>
    pub fn participant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.participant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the participant.</p>
    pub fn set_participant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.participant_id = input;
        self
    }
    /// <p>The identifier of the participant.</p>
    pub fn get_participant_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.participant_id
    }
    /// <p>The role of the participant. For example, is it a customer, agent, or system.</p>
    pub fn participant_role(mut self, input: crate::types::ParticipantRole) -> Self {
        self.participant_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The role of the participant. For example, is it a customer, agent, or system.</p>
    pub fn set_participant_role(mut self, input: ::std::option::Option<crate::types::ParticipantRole>) -> Self {
        self.participant_role = input;
        self
    }
    /// <p>The role of the participant. For example, is it a customer, agent, or system.</p>
    pub fn get_participant_role(&self) -> &::std::option::Option<crate::types::ParticipantRole> {
        &self.participant_role
    }
    /// <p>The display name of the participant. Can be redacted.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the participant. Can be redacted.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the participant. Can be redacted.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>Type of the event. For example, <code>application/vnd.amazonaws.connect.event.participant.left</code>.</p>
    /// This field is required.
    pub fn event_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Type of the event. For example, <code>application/vnd.amazonaws.connect.event.participant.left</code>.</p>
    pub fn set_event_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_type = input;
        self
    }
    /// <p>Type of the event. For example, <code>application/vnd.amazonaws.connect.event.participant.left</code>.</p>
    pub fn get_event_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_type
    }
    /// <p>Field describing the time of the event. It can have different representations of time.</p>
    /// This field is required.
    pub fn time(mut self, input: crate::types::RealTimeContactAnalysisTimeData) -> Self {
        self.time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Field describing the time of the event. It can have different representations of time.</p>
    pub fn set_time(mut self, input: ::std::option::Option<crate::types::RealTimeContactAnalysisTimeData>) -> Self {
        self.time = input;
        self
    }
    /// <p>Field describing the time of the event. It can have different representations of time.</p>
    pub fn get_time(&self) -> &::std::option::Option<crate::types::RealTimeContactAnalysisTimeData> {
        &self.time
    }
    /// Consumes the builder and constructs a [`RealTimeContactAnalysisSegmentEvent`](crate::types::RealTimeContactAnalysisSegmentEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::RealTimeContactAnalysisSegmentEventBuilder::id)
    /// - [`event_type`](crate::types::builders::RealTimeContactAnalysisSegmentEventBuilder::event_type)
    pub fn build(self) -> ::std::result::Result<crate::types::RealTimeContactAnalysisSegmentEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RealTimeContactAnalysisSegmentEvent {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building RealTimeContactAnalysisSegmentEvent",
                )
            })?,
            participant_id: self.participant_id,
            participant_role: self.participant_role,
            display_name: self.display_name,
            event_type: self.event_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_type",
                    "event_type was not specified but it is required when building RealTimeContactAnalysisSegmentEvent",
                )
            })?,
            time: self.time,
        })
    }
}
