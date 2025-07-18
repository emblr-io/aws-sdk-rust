// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the ReplaceRoute action in Amazon EC2.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2ReplaceRouteAction {
    /// <p>A description of the ReplaceRoute action in Amazon EC2.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Information about the IPv4 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub destination_cidr_block: ::std::option::Option<::std::string::String>,
    /// <p>Information about the ID of the prefix list for the route.</p>
    pub destination_prefix_list_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the IPv6 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub destination_ipv6_cidr_block: ::std::option::Option<::std::string::String>,
    /// <p>Information about the ID of an internet gateway or virtual private gateway.</p>
    pub gateway_id: ::std::option::Option<crate::types::ActionTarget>,
    /// <p>Information about the ID of the route table.</p>
    pub route_table_id: ::std::option::Option<crate::types::ActionTarget>,
}
impl Ec2ReplaceRouteAction {
    /// <p>A description of the ReplaceRoute action in Amazon EC2.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Information about the IPv4 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn destination_cidr_block(&self) -> ::std::option::Option<&str> {
        self.destination_cidr_block.as_deref()
    }
    /// <p>Information about the ID of the prefix list for the route.</p>
    pub fn destination_prefix_list_id(&self) -> ::std::option::Option<&str> {
        self.destination_prefix_list_id.as_deref()
    }
    /// <p>Information about the IPv6 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn destination_ipv6_cidr_block(&self) -> ::std::option::Option<&str> {
        self.destination_ipv6_cidr_block.as_deref()
    }
    /// <p>Information about the ID of an internet gateway or virtual private gateway.</p>
    pub fn gateway_id(&self) -> ::std::option::Option<&crate::types::ActionTarget> {
        self.gateway_id.as_ref()
    }
    /// <p>Information about the ID of the route table.</p>
    pub fn route_table_id(&self) -> ::std::option::Option<&crate::types::ActionTarget> {
        self.route_table_id.as_ref()
    }
}
impl Ec2ReplaceRouteAction {
    /// Creates a new builder-style object to manufacture [`Ec2ReplaceRouteAction`](crate::types::Ec2ReplaceRouteAction).
    pub fn builder() -> crate::types::builders::Ec2ReplaceRouteActionBuilder {
        crate::types::builders::Ec2ReplaceRouteActionBuilder::default()
    }
}

/// A builder for [`Ec2ReplaceRouteAction`](crate::types::Ec2ReplaceRouteAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2ReplaceRouteActionBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) destination_cidr_block: ::std::option::Option<::std::string::String>,
    pub(crate) destination_prefix_list_id: ::std::option::Option<::std::string::String>,
    pub(crate) destination_ipv6_cidr_block: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_id: ::std::option::Option<crate::types::ActionTarget>,
    pub(crate) route_table_id: ::std::option::Option<crate::types::ActionTarget>,
}
impl Ec2ReplaceRouteActionBuilder {
    /// <p>A description of the ReplaceRoute action in Amazon EC2.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the ReplaceRoute action in Amazon EC2.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the ReplaceRoute action in Amazon EC2.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Information about the IPv4 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn destination_cidr_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_cidr_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the IPv4 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn set_destination_cidr_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_cidr_block = input;
        self
    }
    /// <p>Information about the IPv4 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn get_destination_cidr_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_cidr_block
    }
    /// <p>Information about the ID of the prefix list for the route.</p>
    pub fn destination_prefix_list_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_prefix_list_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the ID of the prefix list for the route.</p>
    pub fn set_destination_prefix_list_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_prefix_list_id = input;
        self
    }
    /// <p>Information about the ID of the prefix list for the route.</p>
    pub fn get_destination_prefix_list_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_prefix_list_id
    }
    /// <p>Information about the IPv6 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn destination_ipv6_cidr_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_ipv6_cidr_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the IPv6 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn set_destination_ipv6_cidr_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_ipv6_cidr_block = input;
        self
    }
    /// <p>Information about the IPv6 CIDR address block used for the destination match. The value that you provide must match the CIDR of an existing route in the table.</p>
    pub fn get_destination_ipv6_cidr_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_ipv6_cidr_block
    }
    /// <p>Information about the ID of an internet gateway or virtual private gateway.</p>
    pub fn gateway_id(mut self, input: crate::types::ActionTarget) -> Self {
        self.gateway_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the ID of an internet gateway or virtual private gateway.</p>
    pub fn set_gateway_id(mut self, input: ::std::option::Option<crate::types::ActionTarget>) -> Self {
        self.gateway_id = input;
        self
    }
    /// <p>Information about the ID of an internet gateway or virtual private gateway.</p>
    pub fn get_gateway_id(&self) -> &::std::option::Option<crate::types::ActionTarget> {
        &self.gateway_id
    }
    /// <p>Information about the ID of the route table.</p>
    /// This field is required.
    pub fn route_table_id(mut self, input: crate::types::ActionTarget) -> Self {
        self.route_table_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the ID of the route table.</p>
    pub fn set_route_table_id(mut self, input: ::std::option::Option<crate::types::ActionTarget>) -> Self {
        self.route_table_id = input;
        self
    }
    /// <p>Information about the ID of the route table.</p>
    pub fn get_route_table_id(&self) -> &::std::option::Option<crate::types::ActionTarget> {
        &self.route_table_id
    }
    /// Consumes the builder and constructs a [`Ec2ReplaceRouteAction`](crate::types::Ec2ReplaceRouteAction).
    pub fn build(self) -> crate::types::Ec2ReplaceRouteAction {
        crate::types::Ec2ReplaceRouteAction {
            description: self.description,
            destination_cidr_block: self.destination_cidr_block,
            destination_prefix_list_id: self.destination_prefix_list_id,
            destination_ipv6_cidr_block: self.destination_ipv6_cidr_block,
            gateway_id: self.gateway_id,
            route_table_id: self.route_table_id,
        }
    }
}
