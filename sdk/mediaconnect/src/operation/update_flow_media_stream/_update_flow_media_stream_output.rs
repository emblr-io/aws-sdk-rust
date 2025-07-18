// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFlowMediaStreamOutput {
    /// <p>The ARN of the flow that is associated with the media stream that you updated.</p>
    pub flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>The media stream that you updated.</p>
    pub media_stream: ::std::option::Option<crate::types::MediaStream>,
    _request_id: Option<String>,
}
impl UpdateFlowMediaStreamOutput {
    /// <p>The ARN of the flow that is associated with the media stream that you updated.</p>
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
    /// <p>The media stream that you updated.</p>
    pub fn media_stream(&self) -> ::std::option::Option<&crate::types::MediaStream> {
        self.media_stream.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateFlowMediaStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateFlowMediaStreamOutput {
    /// Creates a new builder-style object to manufacture [`UpdateFlowMediaStreamOutput`](crate::operation::update_flow_media_stream::UpdateFlowMediaStreamOutput).
    pub fn builder() -> crate::operation::update_flow_media_stream::builders::UpdateFlowMediaStreamOutputBuilder {
        crate::operation::update_flow_media_stream::builders::UpdateFlowMediaStreamOutputBuilder::default()
    }
}

/// A builder for [`UpdateFlowMediaStreamOutput`](crate::operation::update_flow_media_stream::UpdateFlowMediaStreamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFlowMediaStreamOutputBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) media_stream: ::std::option::Option<crate::types::MediaStream>,
    _request_id: Option<String>,
}
impl UpdateFlowMediaStreamOutputBuilder {
    /// <p>The ARN of the flow that is associated with the media stream that you updated.</p>
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the flow that is associated with the media stream that you updated.</p>
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// <p>The ARN of the flow that is associated with the media stream that you updated.</p>
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// <p>The media stream that you updated.</p>
    pub fn media_stream(mut self, input: crate::types::MediaStream) -> Self {
        self.media_stream = ::std::option::Option::Some(input);
        self
    }
    /// <p>The media stream that you updated.</p>
    pub fn set_media_stream(mut self, input: ::std::option::Option<crate::types::MediaStream>) -> Self {
        self.media_stream = input;
        self
    }
    /// <p>The media stream that you updated.</p>
    pub fn get_media_stream(&self) -> &::std::option::Option<crate::types::MediaStream> {
        &self.media_stream
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateFlowMediaStreamOutput`](crate::operation::update_flow_media_stream::UpdateFlowMediaStreamOutput).
    pub fn build(self) -> crate::operation::update_flow_media_stream::UpdateFlowMediaStreamOutput {
        crate::operation::update_flow_media_stream::UpdateFlowMediaStreamOutput {
            flow_arn: self.flow_arn,
            media_stream: self.media_stream,
            _request_id: self._request_id,
        }
    }
}
