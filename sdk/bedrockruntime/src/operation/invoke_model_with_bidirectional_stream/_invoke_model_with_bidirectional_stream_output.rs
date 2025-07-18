// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::fmt::Debug)]
pub struct InvokeModelWithBidirectionalStreamOutput {
    /// <p>Streaming response from the model in the format specified by the <code>BidirectionalOutputPayloadPart</code> header.</p>
    #[cfg_attr(any(feature = "serde-serialize", feature = "serde-deserialize"), serde(skip))]
    pub body: crate::event_receiver::EventReceiver<
        crate::types::InvokeModelWithBidirectionalStreamOutput,
        crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
    >,
    _request_id: Option<String>,
}
impl InvokeModelWithBidirectionalStreamOutput {
    /// <p>Streaming response from the model in the format specified by the <code>BidirectionalOutputPayloadPart</code> header.</p>
    pub fn body(
        &self,
    ) -> &crate::event_receiver::EventReceiver<
        crate::types::InvokeModelWithBidirectionalStreamOutput,
        crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
    > {
        &self.body
    }
}
impl ::aws_types::request_id::RequestId for InvokeModelWithBidirectionalStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl InvokeModelWithBidirectionalStreamOutput {
    /// Creates a new builder-style object to manufacture [`InvokeModelWithBidirectionalStreamOutput`](crate::operation::invoke_model_with_bidirectional_stream::InvokeModelWithBidirectionalStreamOutput).
    pub fn builder() -> crate::operation::invoke_model_with_bidirectional_stream::builders::InvokeModelWithBidirectionalStreamOutputBuilder {
        crate::operation::invoke_model_with_bidirectional_stream::builders::InvokeModelWithBidirectionalStreamOutputBuilder::default()
    }
}

/// A builder for [`InvokeModelWithBidirectionalStreamOutput`](crate::operation::invoke_model_with_bidirectional_stream::InvokeModelWithBidirectionalStreamOutput).
#[derive(::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvokeModelWithBidirectionalStreamOutputBuilder {
    pub(crate) body: ::std::option::Option<
        crate::event_receiver::EventReceiver<
            crate::types::InvokeModelWithBidirectionalStreamOutput,
            crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
        >,
    >,
    _request_id: Option<String>,
}
impl InvokeModelWithBidirectionalStreamOutputBuilder {
    /// <p>Streaming response from the model in the format specified by the <code>BidirectionalOutputPayloadPart</code> header.</p>
    /// This field is required.
    pub fn body(
        mut self,
        input: crate::event_receiver::EventReceiver<
            crate::types::InvokeModelWithBidirectionalStreamOutput,
            crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
        >,
    ) -> Self {
        self.body = ::std::option::Option::Some(input);
        self
    }
    /// <p>Streaming response from the model in the format specified by the <code>BidirectionalOutputPayloadPart</code> header.</p>
    pub fn set_body(
        mut self,
        input: ::std::option::Option<
            crate::event_receiver::EventReceiver<
                crate::types::InvokeModelWithBidirectionalStreamOutput,
                crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
            >,
        >,
    ) -> Self {
        self.body = input;
        self
    }
    /// <p>Streaming response from the model in the format specified by the <code>BidirectionalOutputPayloadPart</code> header.</p>
    pub fn get_body(
        &self,
    ) -> &::std::option::Option<
        crate::event_receiver::EventReceiver<
            crate::types::InvokeModelWithBidirectionalStreamOutput,
            crate::types::error::InvokeModelWithBidirectionalStreamOutputError,
        >,
    > {
        &self.body
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`InvokeModelWithBidirectionalStreamOutput`](crate::operation::invoke_model_with_bidirectional_stream::InvokeModelWithBidirectionalStreamOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`body`](crate::operation::invoke_model_with_bidirectional_stream::builders::InvokeModelWithBidirectionalStreamOutputBuilder::body)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::invoke_model_with_bidirectional_stream::InvokeModelWithBidirectionalStreamOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::invoke_model_with_bidirectional_stream::InvokeModelWithBidirectionalStreamOutput {
                body: self.body.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "body",
                        "body was not specified but it is required when building InvokeModelWithBidirectionalStreamOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
