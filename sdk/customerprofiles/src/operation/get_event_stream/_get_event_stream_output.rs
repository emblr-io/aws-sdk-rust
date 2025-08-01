// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEventStreamOutput {
    /// <p>The unique name of the domain.</p>
    pub domain_name: ::std::string::String,
    /// <p>A unique identifier for the event stream.</p>
    pub event_stream_arn: ::std::string::String,
    /// <p>The timestamp of when the export was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The operational state of destination stream for export.</p>
    pub state: crate::types::EventStreamState,
    /// <p>The timestamp when the <code>State</code> changed to <code>STOPPED</code>.</p>
    pub stopped_since: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Details regarding the Kinesis stream.</p>
    pub destination_details: ::std::option::Option<crate::types::EventStreamDestinationDetails>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetEventStreamOutput {
    /// <p>The unique name of the domain.</p>
    pub fn domain_name(&self) -> &str {
        use std::ops::Deref;
        self.domain_name.deref()
    }
    /// <p>A unique identifier for the event stream.</p>
    pub fn event_stream_arn(&self) -> &str {
        use std::ops::Deref;
        self.event_stream_arn.deref()
    }
    /// <p>The timestamp of when the export was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The operational state of destination stream for export.</p>
    pub fn state(&self) -> &crate::types::EventStreamState {
        &self.state
    }
    /// <p>The timestamp when the <code>State</code> changed to <code>STOPPED</code>.</p>
    pub fn stopped_since(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.stopped_since.as_ref()
    }
    /// <p>Details regarding the Kinesis stream.</p>
    pub fn destination_details(&self) -> ::std::option::Option<&crate::types::EventStreamDestinationDetails> {
        self.destination_details.as_ref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetEventStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEventStreamOutput {
    /// Creates a new builder-style object to manufacture [`GetEventStreamOutput`](crate::operation::get_event_stream::GetEventStreamOutput).
    pub fn builder() -> crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder {
        crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder::default()
    }
}

/// A builder for [`GetEventStreamOutput`](crate::operation::get_event_stream::GetEventStreamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEventStreamOutputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::EventStreamState>,
    pub(crate) stopped_since: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) destination_details: ::std::option::Option<crate::types::EventStreamDestinationDetails>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetEventStreamOutputBuilder {
    /// <p>The unique name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>A unique identifier for the event stream.</p>
    /// This field is required.
    pub fn event_stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the event stream.</p>
    pub fn set_event_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_stream_arn = input;
        self
    }
    /// <p>A unique identifier for the event stream.</p>
    pub fn get_event_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_stream_arn
    }
    /// <p>The timestamp of when the export was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the export was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the export was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The operational state of destination stream for export.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::EventStreamState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operational state of destination stream for export.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::EventStreamState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The operational state of destination stream for export.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::EventStreamState> {
        &self.state
    }
    /// <p>The timestamp when the <code>State</code> changed to <code>STOPPED</code>.</p>
    pub fn stopped_since(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.stopped_since = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the <code>State</code> changed to <code>STOPPED</code>.</p>
    pub fn set_stopped_since(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.stopped_since = input;
        self
    }
    /// <p>The timestamp when the <code>State</code> changed to <code>STOPPED</code>.</p>
    pub fn get_stopped_since(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.stopped_since
    }
    /// <p>Details regarding the Kinesis stream.</p>
    /// This field is required.
    pub fn destination_details(mut self, input: crate::types::EventStreamDestinationDetails) -> Self {
        self.destination_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details regarding the Kinesis stream.</p>
    pub fn set_destination_details(mut self, input: ::std::option::Option<crate::types::EventStreamDestinationDetails>) -> Self {
        self.destination_details = input;
        self
    }
    /// <p>Details regarding the Kinesis stream.</p>
    pub fn get_destination_details(&self) -> &::std::option::Option<crate::types::EventStreamDestinationDetails> {
        &self.destination_details
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetEventStreamOutput`](crate::operation::get_event_stream::GetEventStreamOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_name`](crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder::domain_name)
    /// - [`event_stream_arn`](crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder::event_stream_arn)
    /// - [`created_at`](crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder::created_at)
    /// - [`state`](crate::operation::get_event_stream::builders::GetEventStreamOutputBuilder::state)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_event_stream::GetEventStreamOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_event_stream::GetEventStreamOutput {
            domain_name: self.domain_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_name",
                    "domain_name was not specified but it is required when building GetEventStreamOutput",
                )
            })?,
            event_stream_arn: self.event_stream_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_stream_arn",
                    "event_stream_arn was not specified but it is required when building GetEventStreamOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetEventStreamOutput",
                )
            })?,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building GetEventStreamOutput",
                )
            })?,
            stopped_since: self.stopped_since,
            destination_details: self.destination_details,
            tags: self.tags,
            _request_id: self._request_id,
        })
    }
}
