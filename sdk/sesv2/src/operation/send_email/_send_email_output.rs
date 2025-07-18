// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A unique message ID that you receive when an email is accepted for sending.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendEmailOutput {
    /// <p>A unique identifier for the message that is generated when the message is accepted.</p><note>
    /// <p>It's possible for Amazon SES to accept a message without sending it. For example, this can happen when the message that you're trying to send has an attachment that contains a virus, or when you send a templated email that contains invalid personalization content.</p>
    /// </note>
    pub message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendEmailOutput {
    /// <p>A unique identifier for the message that is generated when the message is accepted.</p><note>
    /// <p>It's possible for Amazon SES to accept a message without sending it. For example, this can happen when the message that you're trying to send has an attachment that contains a virus, or when you send a templated email that contains invalid personalization content.</p>
    /// </note>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SendEmailOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendEmailOutput {
    /// Creates a new builder-style object to manufacture [`SendEmailOutput`](crate::operation::send_email::SendEmailOutput).
    pub fn builder() -> crate::operation::send_email::builders::SendEmailOutputBuilder {
        crate::operation::send_email::builders::SendEmailOutputBuilder::default()
    }
}

/// A builder for [`SendEmailOutput`](crate::operation::send_email::SendEmailOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendEmailOutputBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendEmailOutputBuilder {
    /// <p>A unique identifier for the message that is generated when the message is accepted.</p><note>
    /// <p>It's possible for Amazon SES to accept a message without sending it. For example, this can happen when the message that you're trying to send has an attachment that contains a virus, or when you send a templated email that contains invalid personalization content.</p>
    /// </note>
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the message that is generated when the message is accepted.</p><note>
    /// <p>It's possible for Amazon SES to accept a message without sending it. For example, this can happen when the message that you're trying to send has an attachment that contains a virus, or when you send a templated email that contains invalid personalization content.</p>
    /// </note>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>A unique identifier for the message that is generated when the message is accepted.</p><note>
    /// <p>It's possible for Amazon SES to accept a message without sending it. For example, this can happen when the message that you're trying to send has an attachment that contains a virus, or when you send a templated email that contains invalid personalization content.</p>
    /// </note>
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
    /// Consumes the builder and constructs a [`SendEmailOutput`](crate::operation::send_email::SendEmailOutput).
    pub fn build(self) -> crate::operation::send_email::SendEmailOutput {
        crate::operation::send_email::SendEmailOutput {
            message_id: self.message_id,
            _request_id: self._request_id,
        }
    }
}
