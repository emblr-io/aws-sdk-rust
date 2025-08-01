// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendDestinationNumberVerificationCodeOutput {
    /// <p>The unique identifier for the message.</p>
    pub message_id: ::std::string::String,
    _request_id: Option<String>,
}
impl SendDestinationNumberVerificationCodeOutput {
    /// <p>The unique identifier for the message.</p>
    pub fn message_id(&self) -> &str {
        use std::ops::Deref;
        self.message_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for SendDestinationNumberVerificationCodeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendDestinationNumberVerificationCodeOutput {
    /// Creates a new builder-style object to manufacture [`SendDestinationNumberVerificationCodeOutput`](crate::operation::send_destination_number_verification_code::SendDestinationNumberVerificationCodeOutput).
    pub fn builder() -> crate::operation::send_destination_number_verification_code::builders::SendDestinationNumberVerificationCodeOutputBuilder {
        crate::operation::send_destination_number_verification_code::builders::SendDestinationNumberVerificationCodeOutputBuilder::default()
    }
}

/// A builder for [`SendDestinationNumberVerificationCodeOutput`](crate::operation::send_destination_number_verification_code::SendDestinationNumberVerificationCodeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendDestinationNumberVerificationCodeOutputBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendDestinationNumberVerificationCodeOutputBuilder {
    /// <p>The unique identifier for the message.</p>
    /// This field is required.
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the message.</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>The unique identifier for the message.</p>
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
    /// Consumes the builder and constructs a [`SendDestinationNumberVerificationCodeOutput`](crate::operation::send_destination_number_verification_code::SendDestinationNumberVerificationCodeOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`message_id`](crate::operation::send_destination_number_verification_code::builders::SendDestinationNumberVerificationCodeOutputBuilder::message_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::send_destination_number_verification_code::SendDestinationNumberVerificationCodeOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::send_destination_number_verification_code::SendDestinationNumberVerificationCodeOutput {
                message_id: self.message_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "message_id",
                        "message_id was not specified but it is required when building SendDestinationNumberVerificationCodeOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
