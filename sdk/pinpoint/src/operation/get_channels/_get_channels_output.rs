// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetChannelsOutput {
    /// <p>Provides information about the general settings and status of all channels for an application, including channels that aren't enabled for the application.</p>
    pub channels_response: ::std::option::Option<crate::types::ChannelsResponse>,
    _request_id: Option<String>,
}
impl GetChannelsOutput {
    /// <p>Provides information about the general settings and status of all channels for an application, including channels that aren't enabled for the application.</p>
    pub fn channels_response(&self) -> ::std::option::Option<&crate::types::ChannelsResponse> {
        self.channels_response.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetChannelsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetChannelsOutput {
    /// Creates a new builder-style object to manufacture [`GetChannelsOutput`](crate::operation::get_channels::GetChannelsOutput).
    pub fn builder() -> crate::operation::get_channels::builders::GetChannelsOutputBuilder {
        crate::operation::get_channels::builders::GetChannelsOutputBuilder::default()
    }
}

/// A builder for [`GetChannelsOutput`](crate::operation::get_channels::GetChannelsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetChannelsOutputBuilder {
    pub(crate) channels_response: ::std::option::Option<crate::types::ChannelsResponse>,
    _request_id: Option<String>,
}
impl GetChannelsOutputBuilder {
    /// <p>Provides information about the general settings and status of all channels for an application, including channels that aren't enabled for the application.</p>
    /// This field is required.
    pub fn channels_response(mut self, input: crate::types::ChannelsResponse) -> Self {
        self.channels_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the general settings and status of all channels for an application, including channels that aren't enabled for the application.</p>
    pub fn set_channels_response(mut self, input: ::std::option::Option<crate::types::ChannelsResponse>) -> Self {
        self.channels_response = input;
        self
    }
    /// <p>Provides information about the general settings and status of all channels for an application, including channels that aren't enabled for the application.</p>
    pub fn get_channels_response(&self) -> &::std::option::Option<crate::types::ChannelsResponse> {
        &self.channels_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetChannelsOutput`](crate::operation::get_channels::GetChannelsOutput).
    pub fn build(self) -> crate::operation::get_channels::GetChannelsOutput {
        crate::operation::get_channels::GetChannelsOutput {
            channels_response: self.channels_response,
            _request_id: self._request_id,
        }
    }
}
