// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutEventsInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a batch of events to process.</p>
    pub events_request: ::std::option::Option<crate::types::EventsRequest>,
}
impl PutEventsInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>Specifies a batch of events to process.</p>
    pub fn events_request(&self) -> ::std::option::Option<&crate::types::EventsRequest> {
        self.events_request.as_ref()
    }
}
impl PutEventsInput {
    /// Creates a new builder-style object to manufacture [`PutEventsInput`](crate::operation::put_events::PutEventsInput).
    pub fn builder() -> crate::operation::put_events::builders::PutEventsInputBuilder {
        crate::operation::put_events::builders::PutEventsInputBuilder::default()
    }
}

/// A builder for [`PutEventsInput`](crate::operation::put_events::PutEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutEventsInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) events_request: ::std::option::Option<crate::types::EventsRequest>,
}
impl PutEventsInputBuilder {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>Specifies a batch of events to process.</p>
    /// This field is required.
    pub fn events_request(mut self, input: crate::types::EventsRequest) -> Self {
        self.events_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a batch of events to process.</p>
    pub fn set_events_request(mut self, input: ::std::option::Option<crate::types::EventsRequest>) -> Self {
        self.events_request = input;
        self
    }
    /// <p>Specifies a batch of events to process.</p>
    pub fn get_events_request(&self) -> &::std::option::Option<crate::types::EventsRequest> {
        &self.events_request
    }
    /// Consumes the builder and constructs a [`PutEventsInput`](crate::operation::put_events::PutEventsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_events::PutEventsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_events::PutEventsInput {
            application_id: self.application_id,
            events_request: self.events_request,
        })
    }
}
