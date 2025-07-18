// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCustomEndpointOutput {
    /// <p>The IoT managed integrations dedicated, custom endpoint for the device to route traffic through.</p>
    pub endpoint_address: ::std::string::String,
    _request_id: Option<String>,
}
impl GetCustomEndpointOutput {
    /// <p>The IoT managed integrations dedicated, custom endpoint for the device to route traffic through.</p>
    pub fn endpoint_address(&self) -> &str {
        use std::ops::Deref;
        self.endpoint_address.deref()
    }
}
impl ::aws_types::request_id::RequestId for GetCustomEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCustomEndpointOutput {
    /// Creates a new builder-style object to manufacture [`GetCustomEndpointOutput`](crate::operation::get_custom_endpoint::GetCustomEndpointOutput).
    pub fn builder() -> crate::operation::get_custom_endpoint::builders::GetCustomEndpointOutputBuilder {
        crate::operation::get_custom_endpoint::builders::GetCustomEndpointOutputBuilder::default()
    }
}

/// A builder for [`GetCustomEndpointOutput`](crate::operation::get_custom_endpoint::GetCustomEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCustomEndpointOutputBuilder {
    pub(crate) endpoint_address: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetCustomEndpointOutputBuilder {
    /// <p>The IoT managed integrations dedicated, custom endpoint for the device to route traffic through.</p>
    /// This field is required.
    pub fn endpoint_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IoT managed integrations dedicated, custom endpoint for the device to route traffic through.</p>
    pub fn set_endpoint_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_address = input;
        self
    }
    /// <p>The IoT managed integrations dedicated, custom endpoint for the device to route traffic through.</p>
    pub fn get_endpoint_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_address
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCustomEndpointOutput`](crate::operation::get_custom_endpoint::GetCustomEndpointOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`endpoint_address`](crate::operation::get_custom_endpoint::builders::GetCustomEndpointOutputBuilder::endpoint_address)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_custom_endpoint::GetCustomEndpointOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_custom_endpoint::GetCustomEndpointOutput {
            endpoint_address: self.endpoint_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "endpoint_address",
                    "endpoint_address was not specified but it is required when building GetCustomEndpointOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
