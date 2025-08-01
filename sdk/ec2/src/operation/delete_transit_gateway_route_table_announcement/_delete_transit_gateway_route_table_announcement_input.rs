// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTransitGatewayRouteTableAnnouncementInput {
    /// <p>The transit gateway route table ID that's being deleted.</p>
    pub transit_gateway_route_table_announcement_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DeleteTransitGatewayRouteTableAnnouncementInput {
    /// <p>The transit gateway route table ID that's being deleted.</p>
    pub fn transit_gateway_route_table_announcement_id(&self) -> ::std::option::Option<&str> {
        self.transit_gateway_route_table_announcement_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DeleteTransitGatewayRouteTableAnnouncementInput {
    /// Creates a new builder-style object to manufacture [`DeleteTransitGatewayRouteTableAnnouncementInput`](crate::operation::delete_transit_gateway_route_table_announcement::DeleteTransitGatewayRouteTableAnnouncementInput).
    pub fn builder(
    ) -> crate::operation::delete_transit_gateway_route_table_announcement::builders::DeleteTransitGatewayRouteTableAnnouncementInputBuilder {
        crate::operation::delete_transit_gateway_route_table_announcement::builders::DeleteTransitGatewayRouteTableAnnouncementInputBuilder::default()
    }
}

/// A builder for [`DeleteTransitGatewayRouteTableAnnouncementInput`](crate::operation::delete_transit_gateway_route_table_announcement::DeleteTransitGatewayRouteTableAnnouncementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTransitGatewayRouteTableAnnouncementInputBuilder {
    pub(crate) transit_gateway_route_table_announcement_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DeleteTransitGatewayRouteTableAnnouncementInputBuilder {
    /// <p>The transit gateway route table ID that's being deleted.</p>
    /// This field is required.
    pub fn transit_gateway_route_table_announcement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transit_gateway_route_table_announcement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transit gateway route table ID that's being deleted.</p>
    pub fn set_transit_gateway_route_table_announcement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transit_gateway_route_table_announcement_id = input;
        self
    }
    /// <p>The transit gateway route table ID that's being deleted.</p>
    pub fn get_transit_gateway_route_table_announcement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transit_gateway_route_table_announcement_id
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
    /// Consumes the builder and constructs a [`DeleteTransitGatewayRouteTableAnnouncementInput`](crate::operation::delete_transit_gateway_route_table_announcement::DeleteTransitGatewayRouteTableAnnouncementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_transit_gateway_route_table_announcement::DeleteTransitGatewayRouteTableAnnouncementInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_transit_gateway_route_table_announcement::DeleteTransitGatewayRouteTableAnnouncementInput {
                transit_gateway_route_table_announcement_id: self.transit_gateway_route_table_announcement_id,
                dry_run: self.dry_run,
            },
        )
    }
}
