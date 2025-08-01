// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLocalGatewayRouteTableVpcAssociationInput {
    /// <p>The ID of the association.</p>
    pub local_gateway_route_table_vpc_association_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteLocalGatewayRouteTableVpcAssociationInput {
    /// <p>The ID of the association.</p>
    pub fn local_gateway_route_table_vpc_association_id(&self) -> ::std::option::Option<&str> {
        self.local_gateway_route_table_vpc_association_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteLocalGatewayRouteTableVpcAssociationInput {
    /// Creates a new builder-style object to manufacture [`DeleteLocalGatewayRouteTableVpcAssociationInput`](crate::operation::delete_local_gateway_route_table_vpc_association::DeleteLocalGatewayRouteTableVpcAssociationInput).
    pub fn builder(
    ) -> crate::operation::delete_local_gateway_route_table_vpc_association::builders::DeleteLocalGatewayRouteTableVpcAssociationInputBuilder {
        crate::operation::delete_local_gateway_route_table_vpc_association::builders::DeleteLocalGatewayRouteTableVpcAssociationInputBuilder::default(
        )
    }
}

/// A builder for [`DeleteLocalGatewayRouteTableVpcAssociationInput`](crate::operation::delete_local_gateway_route_table_vpc_association::DeleteLocalGatewayRouteTableVpcAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLocalGatewayRouteTableVpcAssociationInputBuilder {
    pub(crate) local_gateway_route_table_vpc_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteLocalGatewayRouteTableVpcAssociationInputBuilder {
    /// <p>The ID of the association.</p>
    /// This field is required.
    pub fn local_gateway_route_table_vpc_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_gateway_route_table_vpc_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the association.</p>
    pub fn set_local_gateway_route_table_vpc_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_gateway_route_table_vpc_association_id = input;
        self
    }
    /// <p>The ID of the association.</p>
    pub fn get_local_gateway_route_table_vpc_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_gateway_route_table_vpc_association_id
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`DeleteLocalGatewayRouteTableVpcAssociationInput`](crate::operation::delete_local_gateway_route_table_vpc_association::DeleteLocalGatewayRouteTableVpcAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_local_gateway_route_table_vpc_association::DeleteLocalGatewayRouteTableVpcAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_local_gateway_route_table_vpc_association::DeleteLocalGatewayRouteTableVpcAssociationInput {
                local_gateway_route_table_vpc_association_id: self.local_gateway_route_table_vpc_association_id,
                dry_run: self.dry_run,
            },
        )
    }
}
