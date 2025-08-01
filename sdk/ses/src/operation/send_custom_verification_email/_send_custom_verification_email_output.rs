// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response received when attempting to send the custom verification email.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendCustomVerificationEmailOutput {
    /// <p>The unique message identifier returned from the <code>SendCustomVerificationEmail</code> operation.</p>
    pub message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendCustomVerificationEmailOutput {
    /// <p>The unique message identifier returned from the <code>SendCustomVerificationEmail</code> operation.</p>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SendCustomVerificationEmailOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendCustomVerificationEmailOutput {
    /// Creates a new builder-style object to manufacture [`SendCustomVerificationEmailOutput`](crate::operation::send_custom_verification_email::SendCustomVerificationEmailOutput).
    pub fn builder() -> crate::operation::send_custom_verification_email::builders::SendCustomVerificationEmailOutputBuilder {
        crate::operation::send_custom_verification_email::builders::SendCustomVerificationEmailOutputBuilder::default()
    }
}

/// A builder for [`SendCustomVerificationEmailOutput`](crate::operation::send_custom_verification_email::SendCustomVerificationEmailOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendCustomVerificationEmailOutputBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendCustomVerificationEmailOutputBuilder {
    /// <p>The unique message identifier returned from the <code>SendCustomVerificationEmail</code> operation.</p>
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique message identifier returned from the <code>SendCustomVerificationEmail</code> operation.</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>The unique message identifier returned from the <code>SendCustomVerificationEmail</code> operation.</p>
    pub fn get_message_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SendCustomVerificationEmailOutput`](crate::operation::send_custom_verification_email::SendCustomVerificationEmailOutput).
    pub fn build(self) -> crate::operation::send_custom_verification_email::SendCustomVerificationEmailOutput {
        crate::operation::send_custom_verification_email::SendCustomVerificationEmailOutput {
            message_id: self.message_id,
            _request_id: self._request_id,
        }
    }
}
