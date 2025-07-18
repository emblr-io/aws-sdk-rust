// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApnsChannelOutput {
    /// <p>Provides information about the status and settings of the APNs (Apple Push Notification service) channel for an application.</p>
    pub apns_channel_response: ::std::option::Option<crate::types::ApnsChannelResponse>,
    _request_id: Option<String>,
}
impl GetApnsChannelOutput {
    /// <p>Provides information about the status and settings of the APNs (Apple Push Notification service) channel for an application.</p>
    pub fn apns_channel_response(&self) -> ::std::option::Option<&crate::types::ApnsChannelResponse> {
        self.apns_channel_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetApnsChannelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetApnsChannelOutput {
    /// Creates a new builder-style object to manufacture [`GetApnsChannelOutput`](crate::operation::get_apns_channel::GetApnsChannelOutput).
    pub fn builder() -> crate::operation::get_apns_channel::builders::GetApnsChannelOutputBuilder {
        crate::operation::get_apns_channel::builders::GetApnsChannelOutputBuilder::default()
    }
}

/// A builder for [`GetApnsChannelOutput`](crate::operation::get_apns_channel::GetApnsChannelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApnsChannelOutputBuilder {
    pub(crate) apns_channel_response: ::std::option::Option<crate::types::ApnsChannelResponse>,
    _request_id: Option<String>,
}
impl GetApnsChannelOutputBuilder {
    /// <p>Provides information about the status and settings of the APNs (Apple Push Notification service) channel for an application.</p>
    /// This field is required.
    pub fn apns_channel_response(mut self, input: crate::types::ApnsChannelResponse) -> Self {
        self.apns_channel_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the status and settings of the APNs (Apple Push Notification service) channel for an application.</p>
    pub fn set_apns_channel_response(mut self, input: ::std::option::Option<crate::types::ApnsChannelResponse>) -> Self {
        self.apns_channel_response = input;
        self
    }
    /// <p>Provides information about the status and settings of the APNs (Apple Push Notification service) channel for an application.</p>
    pub fn get_apns_channel_response(&self) -> &::std::option::Option<crate::types::ApnsChannelResponse> {
        &self.apns_channel_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetApnsChannelOutput`](crate::operation::get_apns_channel::GetApnsChannelOutput).
    pub fn build(self) -> crate::operation::get_apns_channel::GetApnsChannelOutput {
        crate::operation::get_apns_channel::GetApnsChannelOutput {
            apns_channel_response: self.apns_channel_response,
            _request_id: self._request_id,
        }
    }
}
