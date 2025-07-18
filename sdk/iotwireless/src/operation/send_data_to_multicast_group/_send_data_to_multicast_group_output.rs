// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendDataToMulticastGroupOutput {
    /// <p>ID of a multicast group message.</p>
    pub message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendDataToMulticastGroupOutput {
    /// <p>ID of a multicast group message.</p>
    pub fn message_id(&self) -> ::std::option::Option<&str> {
        self.message_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SendDataToMulticastGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendDataToMulticastGroupOutput {
    /// Creates a new builder-style object to manufacture [`SendDataToMulticastGroupOutput`](crate::operation::send_data_to_multicast_group::SendDataToMulticastGroupOutput).
    pub fn builder() -> crate::operation::send_data_to_multicast_group::builders::SendDataToMulticastGroupOutputBuilder {
        crate::operation::send_data_to_multicast_group::builders::SendDataToMulticastGroupOutputBuilder::default()
    }
}

/// A builder for [`SendDataToMulticastGroupOutput`](crate::operation::send_data_to_multicast_group::SendDataToMulticastGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendDataToMulticastGroupOutputBuilder {
    pub(crate) message_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SendDataToMulticastGroupOutputBuilder {
    /// <p>ID of a multicast group message.</p>
    pub fn message_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of a multicast group message.</p>
    pub fn set_message_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_id = input;
        self
    }
    /// <p>ID of a multicast group message.</p>
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
    /// Consumes the builder and constructs a [`SendDataToMulticastGroupOutput`](crate::operation::send_data_to_multicast_group::SendDataToMulticastGroupOutput).
    pub fn build(self) -> crate::operation::send_data_to_multicast_group::SendDataToMulticastGroupOutput {
        crate::operation::send_data_to_multicast_group::SendDataToMulticastGroupOutput {
            message_id: self.message_id,
            _request_id: self._request_id,
        }
    }
}
