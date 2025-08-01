// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMeetingInput {
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub meeting_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMeetingInput {
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub fn meeting_id(&self) -> ::std::option::Option<&str> {
        self.meeting_id.as_deref()
    }
}
impl DeleteMeetingInput {
    /// Creates a new builder-style object to manufacture [`DeleteMeetingInput`](crate::operation::delete_meeting::DeleteMeetingInput).
    pub fn builder() -> crate::operation::delete_meeting::builders::DeleteMeetingInputBuilder {
        crate::operation::delete_meeting::builders::DeleteMeetingInputBuilder::default()
    }
}

/// A builder for [`DeleteMeetingInput`](crate::operation::delete_meeting::DeleteMeetingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMeetingInputBuilder {
    pub(crate) meeting_id: ::std::option::Option<::std::string::String>,
}
impl DeleteMeetingInputBuilder {
    /// <p>The Amazon Chime SDK meeting ID.</p>
    /// This field is required.
    pub fn meeting_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.meeting_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub fn set_meeting_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.meeting_id = input;
        self
    }
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub fn get_meeting_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.meeting_id
    }
    /// Consumes the builder and constructs a [`DeleteMeetingInput`](crate::operation::delete_meeting::DeleteMeetingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_meeting::DeleteMeetingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_meeting::DeleteMeetingInput { meeting_id: self.meeting_id })
    }
}
