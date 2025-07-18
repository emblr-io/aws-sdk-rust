// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRouteServerEndpointOutput {
    /// <p>Information about the deleted route server endpoint.</p>
    pub route_server_endpoint: ::std::option::Option<crate::types::RouteServerEndpoint>,
    _request_id: Option<String>,
}
impl DeleteRouteServerEndpointOutput {
    /// <p>Information about the deleted route server endpoint.</p>
    pub fn route_server_endpoint(&self) -> ::std::option::Option<&crate::types::RouteServerEndpoint> {
        self.route_server_endpoint.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteRouteServerEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteRouteServerEndpointOutput {
    /// Creates a new builder-style object to manufacture [`DeleteRouteServerEndpointOutput`](crate::operation::delete_route_server_endpoint::DeleteRouteServerEndpointOutput).
    pub fn builder() -> crate::operation::delete_route_server_endpoint::builders::DeleteRouteServerEndpointOutputBuilder {
        crate::operation::delete_route_server_endpoint::builders::DeleteRouteServerEndpointOutputBuilder::default()
    }
}

/// A builder for [`DeleteRouteServerEndpointOutput`](crate::operation::delete_route_server_endpoint::DeleteRouteServerEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRouteServerEndpointOutputBuilder {
    pub(crate) route_server_endpoint: ::std::option::Option<crate::types::RouteServerEndpoint>,
    _request_id: Option<String>,
}
impl DeleteRouteServerEndpointOutputBuilder {
    /// <p>Information about the deleted route server endpoint.</p>
    pub fn route_server_endpoint(mut self, input: crate::types::RouteServerEndpoint) -> Self {
        self.route_server_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the deleted route server endpoint.</p>
    pub fn set_route_server_endpoint(mut self, input: ::std::option::Option<crate::types::RouteServerEndpoint>) -> Self {
        self.route_server_endpoint = input;
        self
    }
    /// <p>Information about the deleted route server endpoint.</p>
    pub fn get_route_server_endpoint(&self) -> &::std::option::Option<crate::types::RouteServerEndpoint> {
        &self.route_server_endpoint
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteRouteServerEndpointOutput`](crate::operation::delete_route_server_endpoint::DeleteRouteServerEndpointOutput).
    pub fn build(self) -> crate::operation::delete_route_server_endpoint::DeleteRouteServerEndpointOutput {
        crate::operation::delete_route_server_endpoint::DeleteRouteServerEndpointOutput {
            route_server_endpoint: self.route_server_endpoint,
            _request_id: self._request_id,
        }
    }
}
