// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelFlowCallbackOutput {
    /// <p>The ARN of the channel.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>The call back ID passed in the request.</p>
    pub callback_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ChannelFlowCallbackOutput {
    /// <p>The ARN of the channel.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>The call back ID passed in the request.</p>
    pub fn callback_id(&self) -> ::std::option::Option<&str> {
        self.callback_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ChannelFlowCallbackOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ChannelFlowCallbackOutput {
    /// Creates a new builder-style object to manufacture [`ChannelFlowCallbackOutput`](crate::operation::channel_flow_callback::ChannelFlowCallbackOutput).
    pub fn builder() -> crate::operation::channel_flow_callback::builders::ChannelFlowCallbackOutputBuilder {
        crate::operation::channel_flow_callback::builders::ChannelFlowCallbackOutputBuilder::default()
    }
}

/// A builder for [`ChannelFlowCallbackOutput`](crate::operation::channel_flow_callback::ChannelFlowCallbackOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelFlowCallbackOutputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) callback_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ChannelFlowCallbackOutputBuilder {
    /// <p>The ARN of the channel.</p>
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>The call back ID passed in the request.</p>
    pub fn callback_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.callback_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The call back ID passed in the request.</p>
    pub fn set_callback_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.callback_id = input;
        self
    }
    /// <p>The call back ID passed in the request.</p>
    pub fn get_callback_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.callback_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ChannelFlowCallbackOutput`](crate::operation::channel_flow_callback::ChannelFlowCallbackOutput).
    pub fn build(self) -> crate::operation::channel_flow_callback::ChannelFlowCallbackOutput {
        crate::operation::channel_flow_callback::ChannelFlowCallbackOutput {
            channel_arn: self.channel_arn,
            callback_id: self.callback_id,
            _request_id: self._request_id,
        }
    }
}
