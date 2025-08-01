// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateTransitGatewayRouteTableOutput {
    /// <p>The ID of the association.</p>
    pub association: ::std::option::Option<crate::types::TransitGatewayAssociation>,
    _request_id: Option<String>,
}
impl AssociateTransitGatewayRouteTableOutput {
    /// <p>The ID of the association.</p>
    pub fn association(&self) -> ::std::option::Option<&crate::types::TransitGatewayAssociation> {
        self.association.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateTransitGatewayRouteTableOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateTransitGatewayRouteTableOutput {
    /// Creates a new builder-style object to manufacture [`AssociateTransitGatewayRouteTableOutput`](crate::operation::associate_transit_gateway_route_table::AssociateTransitGatewayRouteTableOutput).
    pub fn builder() -> crate::operation::associate_transit_gateway_route_table::builders::AssociateTransitGatewayRouteTableOutputBuilder {
        crate::operation::associate_transit_gateway_route_table::builders::AssociateTransitGatewayRouteTableOutputBuilder::default()
    }
}

/// A builder for [`AssociateTransitGatewayRouteTableOutput`](crate::operation::associate_transit_gateway_route_table::AssociateTransitGatewayRouteTableOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateTransitGatewayRouteTableOutputBuilder {
    pub(crate) association: ::std::option::Option<crate::types::TransitGatewayAssociation>,
    _request_id: Option<String>,
}
impl AssociateTransitGatewayRouteTableOutputBuilder {
    /// <p>The ID of the association.</p>
    pub fn association(mut self, input: crate::types::TransitGatewayAssociation) -> Self {
        self.association = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the association.</p>
    pub fn set_association(mut self, input: ::std::option::Option<crate::types::TransitGatewayAssociation>) -> Self {
        self.association = input;
        self
    }
    /// <p>The ID of the association.</p>
    pub fn get_association(&self) -> &::std::option::Option<crate::types::TransitGatewayAssociation> {
        &self.association
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateTransitGatewayRouteTableOutput`](crate::operation::associate_transit_gateway_route_table::AssociateTransitGatewayRouteTableOutput).
    pub fn build(self) -> crate::operation::associate_transit_gateway_route_table::AssociateTransitGatewayRouteTableOutput {
        crate::operation::associate_transit_gateway_route_table::AssociateTransitGatewayRouteTableOutput {
            association: self.association,
            _request_id: self._request_id,
        }
    }
}
