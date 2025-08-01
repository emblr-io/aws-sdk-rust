// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// The settings for a MediaConnect Flow.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaConnectFlowRequest {
    /// The ARN of the MediaConnect Flow that you want to use as a source.
    pub flow_arn: ::std::option::Option<::std::string::String>,
}
impl MediaConnectFlowRequest {
    /// The ARN of the MediaConnect Flow that you want to use as a source.
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
}
impl MediaConnectFlowRequest {
    /// Creates a new builder-style object to manufacture [`MediaConnectFlowRequest`](crate::types::MediaConnectFlowRequest).
    pub fn builder() -> crate::types::builders::MediaConnectFlowRequestBuilder {
        crate::types::builders::MediaConnectFlowRequestBuilder::default()
    }
}

/// A builder for [`MediaConnectFlowRequest`](crate::types::MediaConnectFlowRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaConnectFlowRequestBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
}
impl MediaConnectFlowRequestBuilder {
    /// The ARN of the MediaConnect Flow that you want to use as a source.
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the MediaConnect Flow that you want to use as a source.
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// The ARN of the MediaConnect Flow that you want to use as a source.
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// Consumes the builder and constructs a [`MediaConnectFlowRequest`](crate::types::MediaConnectFlowRequest).
    pub fn build(self) -> crate::types::MediaConnectFlowRequest {
        crate::types::MediaConnectFlowRequest { flow_arn: self.flow_arn }
    }
}
