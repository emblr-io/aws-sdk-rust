// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAttendeesInput {
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub meeting_id: ::std::option::Option<::std::string::String>,
    /// <p>The token to use to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListAttendeesInput {
    /// <p>The Amazon Chime SDK meeting ID.</p>
    pub fn meeting_id(&self) -> ::std::option::Option<&str> {
        self.meeting_id.as_deref()
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListAttendeesInput {
    /// Creates a new builder-style object to manufacture [`ListAttendeesInput`](crate::operation::list_attendees::ListAttendeesInput).
    pub fn builder() -> crate::operation::list_attendees::builders::ListAttendeesInputBuilder {
        crate::operation::list_attendees::builders::ListAttendeesInputBuilder::default()
    }
}

/// A builder for [`ListAttendeesInput`](crate::operation::list_attendees::ListAttendeesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAttendeesInputBuilder {
    pub(crate) meeting_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListAttendeesInputBuilder {
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
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListAttendeesInput`](crate::operation::list_attendees::ListAttendeesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_attendees::ListAttendeesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_attendees::ListAttendeesInput {
            meeting_id: self.meeting_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
