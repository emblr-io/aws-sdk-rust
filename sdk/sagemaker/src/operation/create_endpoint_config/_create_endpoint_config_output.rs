// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEndpointConfigOutput {
    /// <p>The Amazon Resource Name (ARN) of the endpoint configuration.</p>
    pub endpoint_config_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEndpointConfigOutput {
    /// <p>The Amazon Resource Name (ARN) of the endpoint configuration.</p>
    pub fn endpoint_config_arn(&self) -> ::std::option::Option<&str> {
        self.endpoint_config_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEndpointConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEndpointConfigOutput {
    /// Creates a new builder-style object to manufacture [`CreateEndpointConfigOutput`](crate::operation::create_endpoint_config::CreateEndpointConfigOutput).
    pub fn builder() -> crate::operation::create_endpoint_config::builders::CreateEndpointConfigOutputBuilder {
        crate::operation::create_endpoint_config::builders::CreateEndpointConfigOutputBuilder::default()
    }
}

/// A builder for [`CreateEndpointConfigOutput`](crate::operation::create_endpoint_config::CreateEndpointConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEndpointConfigOutputBuilder {
    pub(crate) endpoint_config_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEndpointConfigOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the endpoint configuration.</p>
    /// This field is required.
    pub fn endpoint_config_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_config_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the endpoint configuration.</p>
    pub fn set_endpoint_config_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_config_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the endpoint configuration.</p>
    pub fn get_endpoint_config_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_config_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEndpointConfigOutput`](crate::operation::create_endpoint_config::CreateEndpointConfigOutput).
    pub fn build(self) -> crate::operation::create_endpoint_config::CreateEndpointConfigOutput {
        crate::operation::create_endpoint_config::CreateEndpointConfigOutput {
            endpoint_config_arn: self.endpoint_config_arn,
            _request_id: self._request_id,
        }
    }
}
