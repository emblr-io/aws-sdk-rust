// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendMessagesOutput {
    /// <p>Provides information about the results of a request to send a message to an endpoint address.</p>
    pub message_response: ::std::option::Option<crate::types::MessageResponse>,
    _request_id: Option<String>,
}
impl SendMessagesOutput {
    /// <p>Provides information about the results of a request to send a message to an endpoint address.</p>
    pub fn message_response(&self) -> ::std::option::Option<&crate::types::MessageResponse> {
        self.message_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for SendMessagesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendMessagesOutput {
    /// Creates a new builder-style object to manufacture [`SendMessagesOutput`](crate::operation::send_messages::SendMessagesOutput).
    pub fn builder() -> crate::operation::send_messages::builders::SendMessagesOutputBuilder {
        crate::operation::send_messages::builders::SendMessagesOutputBuilder::default()
    }
}

/// A builder for [`SendMessagesOutput`](crate::operation::send_messages::SendMessagesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendMessagesOutputBuilder {
    pub(crate) message_response: ::std::option::Option<crate::types::MessageResponse>,
    _request_id: Option<String>,
}
impl SendMessagesOutputBuilder {
    /// <p>Provides information about the results of a request to send a message to an endpoint address.</p>
    /// This field is required.
    pub fn message_response(mut self, input: crate::types::MessageResponse) -> Self {
        self.message_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the results of a request to send a message to an endpoint address.</p>
    pub fn set_message_response(mut self, input: ::std::option::Option<crate::types::MessageResponse>) -> Self {
        self.message_response = input;
        self
    }
    /// <p>Provides information about the results of a request to send a message to an endpoint address.</p>
    pub fn get_message_response(&self) -> &::std::option::Option<crate::types::MessageResponse> {
        &self.message_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SendMessagesOutput`](crate::operation::send_messages::SendMessagesOutput).
    pub fn build(self) -> crate::operation::send_messages::SendMessagesOutput {
        crate::operation::send_messages::SendMessagesOutput {
            message_response: self.message_response,
            _request_id: self._request_id,
        }
    }
}
