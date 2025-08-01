// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEndpointOutput {
    /// <p>The endpoint that was deleted.</p>
    pub endpoint: ::std::option::Option<crate::types::Endpoint>,
    _request_id: Option<String>,
}
impl DeleteEndpointOutput {
    /// <p>The endpoint that was deleted.</p>
    pub fn endpoint(&self) -> ::std::option::Option<&crate::types::Endpoint> {
        self.endpoint.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteEndpointOutput {
    /// Creates a new builder-style object to manufacture [`DeleteEndpointOutput`](crate::operation::delete_endpoint::DeleteEndpointOutput).
    pub fn builder() -> crate::operation::delete_endpoint::builders::DeleteEndpointOutputBuilder {
        crate::operation::delete_endpoint::builders::DeleteEndpointOutputBuilder::default()
    }
}

/// A builder for [`DeleteEndpointOutput`](crate::operation::delete_endpoint::DeleteEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEndpointOutputBuilder {
    pub(crate) endpoint: ::std::option::Option<crate::types::Endpoint>,
    _request_id: Option<String>,
}
impl DeleteEndpointOutputBuilder {
    /// <p>The endpoint that was deleted.</p>
    pub fn endpoint(mut self, input: crate::types::Endpoint) -> Self {
        self.endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>The endpoint that was deleted.</p>
    pub fn set_endpoint(mut self, input: ::std::option::Option<crate::types::Endpoint>) -> Self {
        self.endpoint = input;
        self
    }
    /// <p>The endpoint that was deleted.</p>
    pub fn get_endpoint(&self) -> &::std::option::Option<crate::types::Endpoint> {
        &self.endpoint
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteEndpointOutput`](crate::operation::delete_endpoint::DeleteEndpointOutput).
    pub fn build(self) -> crate::operation::delete_endpoint::DeleteEndpointOutput {
        crate::operation::delete_endpoint::DeleteEndpointOutput {
            endpoint: self.endpoint,
            _request_id: self._request_id,
        }
    }
}
