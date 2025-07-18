// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMeetingDialOutOutput {
    /// <p>Unique ID that tracks API calls.</p>
    pub transaction_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateMeetingDialOutOutput {
    /// <p>Unique ID that tracks API calls.</p>
    pub fn transaction_id(&self) -> ::std::option::Option<&str> {
        self.transaction_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateMeetingDialOutOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateMeetingDialOutOutput {
    /// Creates a new builder-style object to manufacture [`CreateMeetingDialOutOutput`](crate::operation::create_meeting_dial_out::CreateMeetingDialOutOutput).
    pub fn builder() -> crate::operation::create_meeting_dial_out::builders::CreateMeetingDialOutOutputBuilder {
        crate::operation::create_meeting_dial_out::builders::CreateMeetingDialOutOutputBuilder::default()
    }
}

/// A builder for [`CreateMeetingDialOutOutput`](crate::operation::create_meeting_dial_out::CreateMeetingDialOutOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMeetingDialOutOutputBuilder {
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateMeetingDialOutOutputBuilder {
    /// <p>Unique ID that tracks API calls.</p>
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique ID that tracks API calls.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>Unique ID that tracks API calls.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateMeetingDialOutOutput`](crate::operation::create_meeting_dial_out::CreateMeetingDialOutOutput).
    pub fn build(self) -> crate::operation::create_meeting_dial_out::CreateMeetingDialOutOutput {
        crate::operation::create_meeting_dial_out::CreateMeetingDialOutOutput {
            transaction_id: self.transaction_id,
            _request_id: self._request_id,
        }
    }
}
