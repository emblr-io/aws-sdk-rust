// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InvokeEndpointAsyncInput {
    /// <p>The name of the endpoint that you specified when you created the endpoint using the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateEndpoint.html">CreateEndpoint</a> API.</p>
    pub endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The MIME type of the input data in the request body.</p>
    pub content_type: ::std::option::Option<::std::string::String>,
    /// <p>The desired MIME type of the inference response from the model container.</p>
    pub accept: ::std::option::Option<::std::string::String>,
    /// <p>Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6">Section 3.3.6. Field Value Components</a> of the Hypertext Transfer Protocol (HTTP/1.1).</p>
    /// <p>The code in your model is responsible for setting or updating any custom attributes in the response. If your code does not set this value in the response, an empty value is returned. For example, if a custom attribute represents the trace ID, your model can prepend the custom attribute with <code>Trace ID:</code> in your post-processing function.</p>
    /// <p>This feature is currently supported in the Amazon Web Services SDKs but not in the Amazon SageMaker Python SDK.</p>
    pub custom_attributes: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the inference request. Amazon SageMaker will generate an identifier for you if none is specified.</p>
    pub inference_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 URI where the inference request payload is stored.</p>
    pub input_location: ::std::option::Option<::std::string::String>,
    /// <p>Maximum age in seconds a request can be in the queue before it is marked as expired. The default is 6 hours, or 21,600 seconds.</p>
    pub request_ttl_seconds: ::std::option::Option<i32>,
    /// <p>Maximum amount of time in seconds a request can be processed before it is marked as expired. The default is 15 minutes, or 900 seconds.</p>
    pub invocation_timeout_seconds: ::std::option::Option<i32>,
}
impl InvokeEndpointAsyncInput {
    /// <p>The name of the endpoint that you specified when you created the endpoint using the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateEndpoint.html">CreateEndpoint</a> API.</p>
    pub fn endpoint_name(&self) -> ::std::option::Option<&str> {
        self.endpoint_name.as_deref()
    }
    /// <p>The MIME type of the input data in the request body.</p>
    pub fn content_type(&self) -> ::std::option::Option<&str> {
        self.content_type.as_deref()
    }
    /// <p>The desired MIME type of the inference response from the model container.</p>
    pub fn accept(&self) -> ::std::option::Option<&str> {
        self.accept.as_deref()
    }
    /// <p>Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6">Section 3.3.6. Field Value Components</a> of the Hypertext Transfer Protocol (HTTP/1.1).</p>
    /// <p>The code in your model is responsible for setting or updating any custom attributes in the response. If your code does not set this value in the response, an empty value is returned. For example, if a custom attribute represents the trace ID, your model can prepend the custom attribute with <code>Trace ID:</code> in your post-processing function.</p>
    /// <p>This feature is currently supported in the Amazon Web Services SDKs but not in the Amazon SageMaker Python SDK.</p>
    pub fn custom_attributes(&self) -> ::std::option::Option<&str> {
        self.custom_attributes.as_deref()
    }
    /// <p>The identifier for the inference request. Amazon SageMaker will generate an identifier for you if none is specified.</p>
    pub fn inference_id(&self) -> ::std::option::Option<&str> {
        self.inference_id.as_deref()
    }
    /// <p>The Amazon S3 URI where the inference request payload is stored.</p>
    pub fn input_location(&self) -> ::std::option::Option<&str> {
        self.input_location.as_deref()
    }
    /// <p>Maximum age in seconds a request can be in the queue before it is marked as expired. The default is 6 hours, or 21,600 seconds.</p>
    pub fn request_ttl_seconds(&self) -> ::std::option::Option<i32> {
        self.request_ttl_seconds
    }
    /// <p>Maximum amount of time in seconds a request can be processed before it is marked as expired. The default is 15 minutes, or 900 seconds.</p>
    pub fn invocation_timeout_seconds(&self) -> ::std::option::Option<i32> {
        self.invocation_timeout_seconds
    }
}
impl ::std::fmt::Debug for InvokeEndpointAsyncInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeEndpointAsyncInput");
        formatter.field("endpoint_name", &self.endpoint_name);
        formatter.field("content_type", &self.content_type);
        formatter.field("accept", &self.accept);
        formatter.field("custom_attributes", &"*** Sensitive Data Redacted ***");
        formatter.field("inference_id", &self.inference_id);
        formatter.field("input_location", &self.input_location);
        formatter.field("request_ttl_seconds", &self.request_ttl_seconds);
        formatter.field("invocation_timeout_seconds", &self.invocation_timeout_seconds);
        formatter.finish()
    }
}
impl InvokeEndpointAsyncInput {
    /// Creates a new builder-style object to manufacture [`InvokeEndpointAsyncInput`](crate::operation::invoke_endpoint_async::InvokeEndpointAsyncInput).
    pub fn builder() -> crate::operation::invoke_endpoint_async::builders::InvokeEndpointAsyncInputBuilder {
        crate::operation::invoke_endpoint_async::builders::InvokeEndpointAsyncInputBuilder::default()
    }
}

/// A builder for [`InvokeEndpointAsyncInput`](crate::operation::invoke_endpoint_async::InvokeEndpointAsyncInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InvokeEndpointAsyncInputBuilder {
    pub(crate) endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) accept: ::std::option::Option<::std::string::String>,
    pub(crate) custom_attributes: ::std::option::Option<::std::string::String>,
    pub(crate) inference_id: ::std::option::Option<::std::string::String>,
    pub(crate) input_location: ::std::option::Option<::std::string::String>,
    pub(crate) request_ttl_seconds: ::std::option::Option<i32>,
    pub(crate) invocation_timeout_seconds: ::std::option::Option<i32>,
}
impl InvokeEndpointAsyncInputBuilder {
    /// <p>The name of the endpoint that you specified when you created the endpoint using the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateEndpoint.html">CreateEndpoint</a> API.</p>
    /// This field is required.
    pub fn endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the endpoint that you specified when you created the endpoint using the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateEndpoint.html">CreateEndpoint</a> API.</p>
    pub fn set_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_name = input;
        self
    }
    /// <p>The name of the endpoint that you specified when you created the endpoint using the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateEndpoint.html">CreateEndpoint</a> API.</p>
    pub fn get_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_name
    }
    /// <p>The MIME type of the input data in the request body.</p>
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The MIME type of the input data in the request body.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The MIME type of the input data in the request body.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>The desired MIME type of the inference response from the model container.</p>
    pub fn accept(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The desired MIME type of the inference response from the model container.</p>
    pub fn set_accept(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept = input;
        self
    }
    /// <p>The desired MIME type of the inference response from the model container.</p>
    pub fn get_accept(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept
    }
    /// <p>Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6">Section 3.3.6. Field Value Components</a> of the Hypertext Transfer Protocol (HTTP/1.1).</p>
    /// <p>The code in your model is responsible for setting or updating any custom attributes in the response. If your code does not set this value in the response, an empty value is returned. For example, if a custom attribute represents the trace ID, your model can prepend the custom attribute with <code>Trace ID:</code> in your post-processing function.</p>
    /// <p>This feature is currently supported in the Amazon Web Services SDKs but not in the Amazon SageMaker Python SDK.</p>
    pub fn custom_attributes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_attributes = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6">Section 3.3.6. Field Value Components</a> of the Hypertext Transfer Protocol (HTTP/1.1).</p>
    /// <p>The code in your model is responsible for setting or updating any custom attributes in the response. If your code does not set this value in the response, an empty value is returned. For example, if a custom attribute represents the trace ID, your model can prepend the custom attribute with <code>Trace ID:</code> in your post-processing function.</p>
    /// <p>This feature is currently supported in the Amazon Web Services SDKs but not in the Amazon SageMaker Python SDK.</p>
    pub fn set_custom_attributes(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_attributes = input;
        self
    }
    /// <p>Provides additional information about a request for an inference submitted to a model hosted at an Amazon SageMaker endpoint. The information is an opaque value that is forwarded verbatim. You could use this value, for example, to provide an ID that you can use to track a request or to provide other metadata that a service endpoint was programmed to process. The value must consist of no more than 1024 visible US-ASCII characters as specified in <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6">Section 3.3.6. Field Value Components</a> of the Hypertext Transfer Protocol (HTTP/1.1).</p>
    /// <p>The code in your model is responsible for setting or updating any custom attributes in the response. If your code does not set this value in the response, an empty value is returned. For example, if a custom attribute represents the trace ID, your model can prepend the custom attribute with <code>Trace ID:</code> in your post-processing function.</p>
    /// <p>This feature is currently supported in the Amazon Web Services SDKs but not in the Amazon SageMaker Python SDK.</p>
    pub fn get_custom_attributes(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_attributes
    }
    /// <p>The identifier for the inference request. Amazon SageMaker will generate an identifier for you if none is specified.</p>
    pub fn inference_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the inference request. Amazon SageMaker will generate an identifier for you if none is specified.</p>
    pub fn set_inference_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_id = input;
        self
    }
    /// <p>The identifier for the inference request. Amazon SageMaker will generate an identifier for you if none is specified.</p>
    pub fn get_inference_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_id
    }
    /// <p>The Amazon S3 URI where the inference request payload is stored.</p>
    /// This field is required.
    pub fn input_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 URI where the inference request payload is stored.</p>
    pub fn set_input_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_location = input;
        self
    }
    /// <p>The Amazon S3 URI where the inference request payload is stored.</p>
    pub fn get_input_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_location
    }
    /// <p>Maximum age in seconds a request can be in the queue before it is marked as expired. The default is 6 hours, or 21,600 seconds.</p>
    pub fn request_ttl_seconds(mut self, input: i32) -> Self {
        self.request_ttl_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum age in seconds a request can be in the queue before it is marked as expired. The default is 6 hours, or 21,600 seconds.</p>
    pub fn set_request_ttl_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.request_ttl_seconds = input;
        self
    }
    /// <p>Maximum age in seconds a request can be in the queue before it is marked as expired. The default is 6 hours, or 21,600 seconds.</p>
    pub fn get_request_ttl_seconds(&self) -> &::std::option::Option<i32> {
        &self.request_ttl_seconds
    }
    /// <p>Maximum amount of time in seconds a request can be processed before it is marked as expired. The default is 15 minutes, or 900 seconds.</p>
    pub fn invocation_timeout_seconds(mut self, input: i32) -> Self {
        self.invocation_timeout_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum amount of time in seconds a request can be processed before it is marked as expired. The default is 15 minutes, or 900 seconds.</p>
    pub fn set_invocation_timeout_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.invocation_timeout_seconds = input;
        self
    }
    /// <p>Maximum amount of time in seconds a request can be processed before it is marked as expired. The default is 15 minutes, or 900 seconds.</p>
    pub fn get_invocation_timeout_seconds(&self) -> &::std::option::Option<i32> {
        &self.invocation_timeout_seconds
    }
    /// Consumes the builder and constructs a [`InvokeEndpointAsyncInput`](crate::operation::invoke_endpoint_async::InvokeEndpointAsyncInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::invoke_endpoint_async::InvokeEndpointAsyncInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::invoke_endpoint_async::InvokeEndpointAsyncInput {
            endpoint_name: self.endpoint_name,
            content_type: self.content_type,
            accept: self.accept,
            custom_attributes: self.custom_attributes,
            inference_id: self.inference_id,
            input_location: self.input_location,
            request_ttl_seconds: self.request_ttl_seconds,
            invocation_timeout_seconds: self.invocation_timeout_seconds,
        })
    }
}
impl ::std::fmt::Debug for InvokeEndpointAsyncInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeEndpointAsyncInputBuilder");
        formatter.field("endpoint_name", &self.endpoint_name);
        formatter.field("content_type", &self.content_type);
        formatter.field("accept", &self.accept);
        formatter.field("custom_attributes", &"*** Sensitive Data Redacted ***");
        formatter.field("inference_id", &self.inference_id);
        formatter.field("input_location", &self.input_location);
        formatter.field("request_ttl_seconds", &self.request_ttl_seconds);
        formatter.field("invocation_timeout_seconds", &self.invocation_timeout_seconds);
        formatter.finish()
    }
}
