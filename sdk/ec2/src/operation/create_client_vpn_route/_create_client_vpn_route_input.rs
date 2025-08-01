// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateClientVpnRouteInput {
    /// <p>The ID of the Client VPN endpoint to which to add the route.</p>
    pub client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The IPv4 address range, in CIDR notation, of the route destination. For example:</p>
    /// <ul>
    /// <li>
    /// <p>To add a route for Internet access, enter <code>0.0.0.0/0</code></p></li>
    /// <li>
    /// <p>To add a route for a peered VPC, enter the peered VPC's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for an on-premises network, enter the Amazon Web Services Site-to-Site VPN connection's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for the local network, enter the client CIDR range</p></li>
    /// </ul>
    pub destination_cidr_block: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subnet through which you want to route traffic. The specified subnet must be an existing target network of the Client VPN endpoint.</p>
    /// <p>Alternatively, if you're adding a route for the local network, specify <code>local</code>.</p>
    pub target_vpc_subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>A brief description of the route.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl CreateClientVpnRouteInput {
    /// <p>The ID of the Client VPN endpoint to which to add the route.</p>
    pub fn client_vpn_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.client_vpn_endpoint_id.as_deref()
    }
    /// <p>The IPv4 address range, in CIDR notation, of the route destination. For example:</p>
    /// <ul>
    /// <li>
    /// <p>To add a route for Internet access, enter <code>0.0.0.0/0</code></p></li>
    /// <li>
    /// <p>To add a route for a peered VPC, enter the peered VPC's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for an on-premises network, enter the Amazon Web Services Site-to-Site VPN connection's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for the local network, enter the client CIDR range</p></li>
    /// </ul>
    pub fn destination_cidr_block(&self) -> ::std::option::Option<&str> {
        self.destination_cidr_block.as_deref()
    }
    /// <p>The ID of the subnet through which you want to route traffic. The specified subnet must be an existing target network of the Client VPN endpoint.</p>
    /// <p>Alternatively, if you're adding a route for the local network, specify <code>local</code>.</p>
    pub fn target_vpc_subnet_id(&self) -> ::std::option::Option<&str> {
        self.target_vpc_subnet_id.as_deref()
    }
    /// <p>A brief description of the route.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl CreateClientVpnRouteInput {
    /// Creates a new builder-style object to manufacture [`CreateClientVpnRouteInput`](crate::operation::create_client_vpn_route::CreateClientVpnRouteInput).
    pub fn builder() -> crate::operation::create_client_vpn_route::builders::CreateClientVpnRouteInputBuilder {
        crate::operation::create_client_vpn_route::builders::CreateClientVpnRouteInputBuilder::default()
    }
}

/// A builder for [`CreateClientVpnRouteInput`](crate::operation::create_client_vpn_route::CreateClientVpnRouteInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateClientVpnRouteInputBuilder {
    pub(crate) client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) destination_cidr_block: ::std::option::Option<::std::string::String>,
    pub(crate) target_vpc_subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl CreateClientVpnRouteInputBuilder {
    /// <p>The ID of the Client VPN endpoint to which to add the route.</p>
    /// This field is required.
    pub fn client_vpn_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Client VPN endpoint to which to add the route.</p>
    pub fn set_client_vpn_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = input;
        self
    }
    /// <p>The ID of the Client VPN endpoint to which to add the route.</p>
    pub fn get_client_vpn_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_vpn_endpoint_id
    }
    /// <p>The IPv4 address range, in CIDR notation, of the route destination. For example:</p>
    /// <ul>
    /// <li>
    /// <p>To add a route for Internet access, enter <code>0.0.0.0/0</code></p></li>
    /// <li>
    /// <p>To add a route for a peered VPC, enter the peered VPC's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for an on-premises network, enter the Amazon Web Services Site-to-Site VPN connection's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for the local network, enter the client CIDR range</p></li>
    /// </ul>
    /// This field is required.
    pub fn destination_cidr_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_cidr_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 address range, in CIDR notation, of the route destination. For example:</p>
    /// <ul>
    /// <li>
    /// <p>To add a route for Internet access, enter <code>0.0.0.0/0</code></p></li>
    /// <li>
    /// <p>To add a route for a peered VPC, enter the peered VPC's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for an on-premises network, enter the Amazon Web Services Site-to-Site VPN connection's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for the local network, enter the client CIDR range</p></li>
    /// </ul>
    pub fn set_destination_cidr_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_cidr_block = input;
        self
    }
    /// <p>The IPv4 address range, in CIDR notation, of the route destination. For example:</p>
    /// <ul>
    /// <li>
    /// <p>To add a route for Internet access, enter <code>0.0.0.0/0</code></p></li>
    /// <li>
    /// <p>To add a route for a peered VPC, enter the peered VPC's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for an on-premises network, enter the Amazon Web Services Site-to-Site VPN connection's IPv4 CIDR range</p></li>
    /// <li>
    /// <p>To add a route for the local network, enter the client CIDR range</p></li>
    /// </ul>
    pub fn get_destination_cidr_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_cidr_block
    }
    /// <p>The ID of the subnet through which you want to route traffic. The specified subnet must be an existing target network of the Client VPN endpoint.</p>
    /// <p>Alternatively, if you're adding a route for the local network, specify <code>local</code>.</p>
    /// This field is required.
    pub fn target_vpc_subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_vpc_subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet through which you want to route traffic. The specified subnet must be an existing target network of the Client VPN endpoint.</p>
    /// <p>Alternatively, if you're adding a route for the local network, specify <code>local</code>.</p>
    pub fn set_target_vpc_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_vpc_subnet_id = input;
        self
    }
    /// <p>The ID of the subnet through which you want to route traffic. The specified subnet must be an existing target network of the Client VPN endpoint.</p>
    /// <p>Alternatively, if you're adding a route for the local network, specify <code>local</code>.</p>
    pub fn get_target_vpc_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_vpc_subnet_id
    }
    /// <p>A brief description of the route.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the route.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description of the route.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
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
    /// Consumes the builder and constructs a [`CreateClientVpnRouteInput`](crate::operation::create_client_vpn_route::CreateClientVpnRouteInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_client_vpn_route::CreateClientVpnRouteInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_client_vpn_route::CreateClientVpnRouteInput {
            client_vpn_endpoint_id: self.client_vpn_endpoint_id,
            destination_cidr_block: self.destination_cidr_block,
            target_vpc_subnet_id: self.target_vpc_subnet_id,
            description: self.description,
            client_token: self.client_token,
            dry_run: self.dry_run,
        })
    }
}
