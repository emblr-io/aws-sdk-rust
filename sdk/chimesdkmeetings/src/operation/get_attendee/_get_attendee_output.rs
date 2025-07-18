// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAttendeeOutput {
    /// <p>The Amazon Chime SDK attendee information.</p>
    pub attendee: ::std::option::Option<crate::types::Attendee>,
    _request_id: Option<String>,
}
impl GetAttendeeOutput {
    /// <p>The Amazon Chime SDK attendee information.</p>
    pub fn attendee(&self) -> ::std::option::Option<&crate::types::Attendee> {
        self.attendee.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAttendeeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAttendeeOutput {
    /// Creates a new builder-style object to manufacture [`GetAttendeeOutput`](crate::operation::get_attendee::GetAttendeeOutput).
    pub fn builder() -> crate::operation::get_attendee::builders::GetAttendeeOutputBuilder {
        crate::operation::get_attendee::builders::GetAttendeeOutputBuilder::default()
    }
}

/// A builder for [`GetAttendeeOutput`](crate::operation::get_attendee::GetAttendeeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAttendeeOutputBuilder {
    pub(crate) attendee: ::std::option::Option<crate::types::Attendee>,
    _request_id: Option<String>,
}
impl GetAttendeeOutputBuilder {
    /// <p>The Amazon Chime SDK attendee information.</p>
    pub fn attendee(mut self, input: crate::types::Attendee) -> Self {
        self.attendee = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Chime SDK attendee information.</p>
    pub fn set_attendee(mut self, input: ::std::option::Option<crate::types::Attendee>) -> Self {
        self.attendee = input;
        self
    }
    /// <p>The Amazon Chime SDK attendee information.</p>
    pub fn get_attendee(&self) -> &::std::option::Option<crate::types::Attendee> {
        &self.attendee
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAttendeeOutput`](crate::operation::get_attendee::GetAttendeeOutput).
    pub fn build(self) -> crate::operation::get_attendee::GetAttendeeOutput {
        crate::operation::get_attendee::GetAttendeeOutput {
            attendee: self.attendee,
            _request_id: self._request_id,
        }
    }
}
