// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableHttpEndpointOutput {
    /// <p>The ARN of the DB cluster.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the HTTP endpoint is enabled or disabled for the DB cluster.</p>
    pub http_endpoint_enabled: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl EnableHttpEndpointOutput {
    /// <p>The ARN of the DB cluster.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Indicates whether the HTTP endpoint is enabled or disabled for the DB cluster.</p>
    pub fn http_endpoint_enabled(&self) -> ::std::option::Option<bool> {
        self.http_endpoint_enabled
    }
}
impl ::aws_types::request_id::RequestId for EnableHttpEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl EnableHttpEndpointOutput {
    /// Creates a new builder-style object to manufacture [`EnableHttpEndpointOutput`](crate::operation::enable_http_endpoint::EnableHttpEndpointOutput).
    pub fn builder() -> crate::operation::enable_http_endpoint::builders::EnableHttpEndpointOutputBuilder {
        crate::operation::enable_http_endpoint::builders::EnableHttpEndpointOutputBuilder::default()
    }
}

/// A builder for [`EnableHttpEndpointOutput`](crate::operation::enable_http_endpoint::EnableHttpEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableHttpEndpointOutputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) http_endpoint_enabled: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl EnableHttpEndpointOutputBuilder {
    /// <p>The ARN of the DB cluster.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the DB cluster.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>Indicates whether the HTTP endpoint is enabled or disabled for the DB cluster.</p>
    pub fn http_endpoint_enabled(mut self, input: bool) -> Self {
        self.http_endpoint_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the HTTP endpoint is enabled or disabled for the DB cluster.</p>
    pub fn set_http_endpoint_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.http_endpoint_enabled = input;
        self
    }
    /// <p>Indicates whether the HTTP endpoint is enabled or disabled for the DB cluster.</p>
    pub fn get_http_endpoint_enabled(&self) -> &::std::option::Option<bool> {
        &self.http_endpoint_enabled
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`EnableHttpEndpointOutput`](crate::operation::enable_http_endpoint::EnableHttpEndpointOutput).
    pub fn build(self) -> crate::operation::enable_http_endpoint::EnableHttpEndpointOutput {
        crate::operation::enable_http_endpoint::EnableHttpEndpointOutput {
            resource_arn: self.resource_arn,
            http_endpoint_enabled: self.http_endpoint_enabled,
            _request_id: self._request_id,
        }
    }
}
