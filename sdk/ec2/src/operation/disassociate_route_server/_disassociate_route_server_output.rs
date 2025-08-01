// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateRouteServerOutput {
    /// <p>Information about the disassociated route server.</p>
    pub route_server_association: ::std::option::Option<crate::types::RouteServerAssociation>,
    _request_id: Option<String>,
}
impl DisassociateRouteServerOutput {
    /// <p>Information about the disassociated route server.</p>
    pub fn route_server_association(&self) -> ::std::option::Option<&crate::types::RouteServerAssociation> {
        self.route_server_association.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DisassociateRouteServerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateRouteServerOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateRouteServerOutput`](crate::operation::disassociate_route_server::DisassociateRouteServerOutput).
    pub fn builder() -> crate::operation::disassociate_route_server::builders::DisassociateRouteServerOutputBuilder {
        crate::operation::disassociate_route_server::builders::DisassociateRouteServerOutputBuilder::default()
    }
}

/// A builder for [`DisassociateRouteServerOutput`](crate::operation::disassociate_route_server::DisassociateRouteServerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateRouteServerOutputBuilder {
    pub(crate) route_server_association: ::std::option::Option<crate::types::RouteServerAssociation>,
    _request_id: Option<String>,
}
impl DisassociateRouteServerOutputBuilder {
    /// <p>Information about the disassociated route server.</p>
    pub fn route_server_association(mut self, input: crate::types::RouteServerAssociation) -> Self {
        self.route_server_association = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the disassociated route server.</p>
    pub fn set_route_server_association(mut self, input: ::std::option::Option<crate::types::RouteServerAssociation>) -> Self {
        self.route_server_association = input;
        self
    }
    /// <p>Information about the disassociated route server.</p>
    pub fn get_route_server_association(&self) -> &::std::option::Option<crate::types::RouteServerAssociation> {
        &self.route_server_association
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateRouteServerOutput`](crate::operation::disassociate_route_server::DisassociateRouteServerOutput).
    pub fn build(self) -> crate::operation::disassociate_route_server::DisassociateRouteServerOutput {
        crate::operation::disassociate_route_server::DisassociateRouteServerOutput {
            route_server_association: self.route_server_association,
            _request_id: self._request_id,
        }
    }
}
