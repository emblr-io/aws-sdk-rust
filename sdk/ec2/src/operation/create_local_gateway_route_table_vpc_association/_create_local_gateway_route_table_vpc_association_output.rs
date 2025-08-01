// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLocalGatewayRouteTableVpcAssociationOutput {
    /// <p>Information about the association.</p>
    pub local_gateway_route_table_vpc_association: ::std::option::Option<crate::types::LocalGatewayRouteTableVpcAssociation>,
    _request_id: Option<String>,
}
impl CreateLocalGatewayRouteTableVpcAssociationOutput {
    /// <p>Information about the association.</p>
    pub fn local_gateway_route_table_vpc_association(&self) -> ::std::option::Option<&crate::types::LocalGatewayRouteTableVpcAssociation> {
        self.local_gateway_route_table_vpc_association.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateLocalGatewayRouteTableVpcAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateLocalGatewayRouteTableVpcAssociationOutput {
    /// Creates a new builder-style object to manufacture [`CreateLocalGatewayRouteTableVpcAssociationOutput`](crate::operation::create_local_gateway_route_table_vpc_association::CreateLocalGatewayRouteTableVpcAssociationOutput).
    pub fn builder(
    ) -> crate::operation::create_local_gateway_route_table_vpc_association::builders::CreateLocalGatewayRouteTableVpcAssociationOutputBuilder {
        crate::operation::create_local_gateway_route_table_vpc_association::builders::CreateLocalGatewayRouteTableVpcAssociationOutputBuilder::default(
        )
    }
}

/// A builder for [`CreateLocalGatewayRouteTableVpcAssociationOutput`](crate::operation::create_local_gateway_route_table_vpc_association::CreateLocalGatewayRouteTableVpcAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateLocalGatewayRouteTableVpcAssociationOutputBuilder {
    pub(crate) local_gateway_route_table_vpc_association: ::std::option::Option<crate::types::LocalGatewayRouteTableVpcAssociation>,
    _request_id: Option<String>,
}
impl CreateLocalGatewayRouteTableVpcAssociationOutputBuilder {
    /// <p>Information about the association.</p>
    pub fn local_gateway_route_table_vpc_association(mut self, input: crate::types::LocalGatewayRouteTableVpcAssociation) -> Self {
        self.local_gateway_route_table_vpc_association = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the association.</p>
    pub fn set_local_gateway_route_table_vpc_association(
        mut self,
        input: ::std::option::Option<crate::types::LocalGatewayRouteTableVpcAssociation>,
    ) -> Self {
        self.local_gateway_route_table_vpc_association = input;
        self
    }
    /// <p>Information about the association.</p>
    pub fn get_local_gateway_route_table_vpc_association(&self) -> &::std::option::Option<crate::types::LocalGatewayRouteTableVpcAssociation> {
        &self.local_gateway_route_table_vpc_association
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateLocalGatewayRouteTableVpcAssociationOutput`](crate::operation::create_local_gateway_route_table_vpc_association::CreateLocalGatewayRouteTableVpcAssociationOutput).
    pub fn build(self) -> crate::operation::create_local_gateway_route_table_vpc_association::CreateLocalGatewayRouteTableVpcAssociationOutput {
        crate::operation::create_local_gateway_route_table_vpc_association::CreateLocalGatewayRouteTableVpcAssociationOutput {
            local_gateway_route_table_vpc_association: self.local_gateway_route_table_vpc_association,
            _request_id: self._request_id,
        }
    }
}
