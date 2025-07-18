// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a route in the route server's routing database.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteServerRoute {
    /// <p>The ID of the route server endpoint that received this route.</p>
    pub route_server_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the route server peer that advertised this route.</p>
    pub route_server_peer_id: ::std::option::Option<::std::string::String>,
    /// <p>Details about the installation status of this route in route tables.</p>
    pub route_installation_details: ::std::option::Option<::std::vec::Vec<crate::types::RouteServerRouteInstallationDetail>>,
    /// <p>The current status of the route in the routing database. Values are <code>in-rib</code> or <code>in-fib</code> depending on if the routes are in the RIB or the FIB database.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Routing_table">Routing Information Base (RIB)</a> serves as a database that stores all the routing information and network topology data collected by a router or routing system, such as routes learned from BGP peers. The RIB is constantly updated as new routing information is received or existing routes change. This ensures that the route server always has the most current view of the network topology and can make optimal routing decisions.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Forwarding_information_base">Forwarding Information Base (FIB)</a> serves as a forwarding table for what route server has determined are the best-path routes in the RIB after evaluating all available routing information and policies. The FIB routes are installed on the route tables. The FIB is recomputed whenever there are changes to the RIB.</p>
    pub route_status: ::std::option::Option<crate::types::RouteServerRouteStatus>,
    /// <p>The destination CIDR block of the route.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>The AS path attributes of the BGP route.</p>
    pub as_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Multi-Exit Discriminator (MED) value of the BGP route.</p>
    pub med: ::std::option::Option<i32>,
    /// <p>The IP address for the next hop.</p>
    pub next_hop_ip: ::std::option::Option<::std::string::String>,
}
impl RouteServerRoute {
    /// <p>The ID of the route server endpoint that received this route.</p>
    pub fn route_server_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.route_server_endpoint_id.as_deref()
    }
    /// <p>The ID of the route server peer that advertised this route.</p>
    pub fn route_server_peer_id(&self) -> ::std::option::Option<&str> {
        self.route_server_peer_id.as_deref()
    }
    /// <p>Details about the installation status of this route in route tables.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.route_installation_details.is_none()`.
    pub fn route_installation_details(&self) -> &[crate::types::RouteServerRouteInstallationDetail] {
        self.route_installation_details.as_deref().unwrap_or_default()
    }
    /// <p>The current status of the route in the routing database. Values are <code>in-rib</code> or <code>in-fib</code> depending on if the routes are in the RIB or the FIB database.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Routing_table">Routing Information Base (RIB)</a> serves as a database that stores all the routing information and network topology data collected by a router or routing system, such as routes learned from BGP peers. The RIB is constantly updated as new routing information is received or existing routes change. This ensures that the route server always has the most current view of the network topology and can make optimal routing decisions.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Forwarding_information_base">Forwarding Information Base (FIB)</a> serves as a forwarding table for what route server has determined are the best-path routes in the RIB after evaluating all available routing information and policies. The FIB routes are installed on the route tables. The FIB is recomputed whenever there are changes to the RIB.</p>
    pub fn route_status(&self) -> ::std::option::Option<&crate::types::RouteServerRouteStatus> {
        self.route_status.as_ref()
    }
    /// <p>The destination CIDR block of the route.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>The AS path attributes of the BGP route.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.as_paths.is_none()`.
    pub fn as_paths(&self) -> &[::std::string::String] {
        self.as_paths.as_deref().unwrap_or_default()
    }
    /// <p>The Multi-Exit Discriminator (MED) value of the BGP route.</p>
    pub fn med(&self) -> ::std::option::Option<i32> {
        self.med
    }
    /// <p>The IP address for the next hop.</p>
    pub fn next_hop_ip(&self) -> ::std::option::Option<&str> {
        self.next_hop_ip.as_deref()
    }
}
impl RouteServerRoute {
    /// Creates a new builder-style object to manufacture [`RouteServerRoute`](crate::types::RouteServerRoute).
    pub fn builder() -> crate::types::builders::RouteServerRouteBuilder {
        crate::types::builders::RouteServerRouteBuilder::default()
    }
}

/// A builder for [`RouteServerRoute`](crate::types::RouteServerRoute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteServerRouteBuilder {
    pub(crate) route_server_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) route_server_peer_id: ::std::option::Option<::std::string::String>,
    pub(crate) route_installation_details: ::std::option::Option<::std::vec::Vec<crate::types::RouteServerRouteInstallationDetail>>,
    pub(crate) route_status: ::std::option::Option<crate::types::RouteServerRouteStatus>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) as_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) med: ::std::option::Option<i32>,
    pub(crate) next_hop_ip: ::std::option::Option<::std::string::String>,
}
impl RouteServerRouteBuilder {
    /// <p>The ID of the route server endpoint that received this route.</p>
    pub fn route_server_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_server_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the route server endpoint that received this route.</p>
    pub fn set_route_server_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_server_endpoint_id = input;
        self
    }
    /// <p>The ID of the route server endpoint that received this route.</p>
    pub fn get_route_server_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_server_endpoint_id
    }
    /// <p>The ID of the route server peer that advertised this route.</p>
    pub fn route_server_peer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_server_peer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the route server peer that advertised this route.</p>
    pub fn set_route_server_peer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_server_peer_id = input;
        self
    }
    /// <p>The ID of the route server peer that advertised this route.</p>
    pub fn get_route_server_peer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_server_peer_id
    }
    /// Appends an item to `route_installation_details`.
    ///
    /// To override the contents of this collection use [`set_route_installation_details`](Self::set_route_installation_details).
    ///
    /// <p>Details about the installation status of this route in route tables.</p>
    pub fn route_installation_details(mut self, input: crate::types::RouteServerRouteInstallationDetail) -> Self {
        let mut v = self.route_installation_details.unwrap_or_default();
        v.push(input);
        self.route_installation_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details about the installation status of this route in route tables.</p>
    pub fn set_route_installation_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::RouteServerRouteInstallationDetail>>,
    ) -> Self {
        self.route_installation_details = input;
        self
    }
    /// <p>Details about the installation status of this route in route tables.</p>
    pub fn get_route_installation_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RouteServerRouteInstallationDetail>> {
        &self.route_installation_details
    }
    /// <p>The current status of the route in the routing database. Values are <code>in-rib</code> or <code>in-fib</code> depending on if the routes are in the RIB or the FIB database.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Routing_table">Routing Information Base (RIB)</a> serves as a database that stores all the routing information and network topology data collected by a router or routing system, such as routes learned from BGP peers. The RIB is constantly updated as new routing information is received or existing routes change. This ensures that the route server always has the most current view of the network topology and can make optimal routing decisions.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Forwarding_information_base">Forwarding Information Base (FIB)</a> serves as a forwarding table for what route server has determined are the best-path routes in the RIB after evaluating all available routing information and policies. The FIB routes are installed on the route tables. The FIB is recomputed whenever there are changes to the RIB.</p>
    pub fn route_status(mut self, input: crate::types::RouteServerRouteStatus) -> Self {
        self.route_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the route in the routing database. Values are <code>in-rib</code> or <code>in-fib</code> depending on if the routes are in the RIB or the FIB database.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Routing_table">Routing Information Base (RIB)</a> serves as a database that stores all the routing information and network topology data collected by a router or routing system, such as routes learned from BGP peers. The RIB is constantly updated as new routing information is received or existing routes change. This ensures that the route server always has the most current view of the network topology and can make optimal routing decisions.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Forwarding_information_base">Forwarding Information Base (FIB)</a> serves as a forwarding table for what route server has determined are the best-path routes in the RIB after evaluating all available routing information and policies. The FIB routes are installed on the route tables. The FIB is recomputed whenever there are changes to the RIB.</p>
    pub fn set_route_status(mut self, input: ::std::option::Option<crate::types::RouteServerRouteStatus>) -> Self {
        self.route_status = input;
        self
    }
    /// <p>The current status of the route in the routing database. Values are <code>in-rib</code> or <code>in-fib</code> depending on if the routes are in the RIB or the FIB database.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Routing_table">Routing Information Base (RIB)</a> serves as a database that stores all the routing information and network topology data collected by a router or routing system, such as routes learned from BGP peers. The RIB is constantly updated as new routing information is received or existing routes change. This ensures that the route server always has the most current view of the network topology and can make optimal routing decisions.</p>
    /// <p>The <a href="https://en.wikipedia.org/wiki/Forwarding_information_base">Forwarding Information Base (FIB)</a> serves as a forwarding table for what route server has determined are the best-path routes in the RIB after evaluating all available routing information and policies. The FIB routes are installed on the route tables. The FIB is recomputed whenever there are changes to the RIB.</p>
    pub fn get_route_status(&self) -> &::std::option::Option<crate::types::RouteServerRouteStatus> {
        &self.route_status
    }
    /// <p>The destination CIDR block of the route.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The destination CIDR block of the route.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The destination CIDR block of the route.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Appends an item to `as_paths`.
    ///
    /// To override the contents of this collection use [`set_as_paths`](Self::set_as_paths).
    ///
    /// <p>The AS path attributes of the BGP route.</p>
    pub fn as_paths(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.as_paths.unwrap_or_default();
        v.push(input.into());
        self.as_paths = ::std::option::Option::Some(v);
        self
    }
    /// <p>The AS path attributes of the BGP route.</p>
    pub fn set_as_paths(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.as_paths = input;
        self
    }
    /// <p>The AS path attributes of the BGP route.</p>
    pub fn get_as_paths(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.as_paths
    }
    /// <p>The Multi-Exit Discriminator (MED) value of the BGP route.</p>
    pub fn med(mut self, input: i32) -> Self {
        self.med = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Multi-Exit Discriminator (MED) value of the BGP route.</p>
    pub fn set_med(mut self, input: ::std::option::Option<i32>) -> Self {
        self.med = input;
        self
    }
    /// <p>The Multi-Exit Discriminator (MED) value of the BGP route.</p>
    pub fn get_med(&self) -> &::std::option::Option<i32> {
        &self.med
    }
    /// <p>The IP address for the next hop.</p>
    pub fn next_hop_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_hop_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address for the next hop.</p>
    pub fn set_next_hop_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_hop_ip = input;
        self
    }
    /// <p>The IP address for the next hop.</p>
    pub fn get_next_hop_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_hop_ip
    }
    /// Consumes the builder and constructs a [`RouteServerRoute`](crate::types::RouteServerRoute).
    pub fn build(self) -> crate::types::RouteServerRoute {
        crate::types::RouteServerRoute {
            route_server_endpoint_id: self.route_server_endpoint_id,
            route_server_peer_id: self.route_server_peer_id,
            route_installation_details: self.route_installation_details,
            route_status: self.route_status,
            prefix: self.prefix,
            as_paths: self.as_paths,
            med: self.med,
            next_hop_ip: self.next_hop_ip,
        }
    }
}
