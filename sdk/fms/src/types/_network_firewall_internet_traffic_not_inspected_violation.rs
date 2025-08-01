// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Violation detail for the subnet for which internet traffic that hasn't been inspected.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkFirewallInternetTrafficNotInspectedViolation {
    /// <p>The subnet ID.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>The subnet Availability Zone.</p>
    pub subnet_availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>Information about the route table ID.</p>
    pub route_table_id: ::std::option::Option<::std::string::String>,
    /// <p>The route or routes that are in violation.</p>
    pub violating_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    /// <p>Information about whether the route table is used in another Availability Zone.</p>
    pub is_route_table_used_in_different_az: bool,
    /// <p>Information about the subnet route table for the current firewall.</p>
    pub current_firewall_subnet_route_table: ::std::option::Option<::std::string::String>,
    /// <p>The expected endpoint for the current firewall.</p>
    pub expected_firewall_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The firewall subnet ID.</p>
    pub firewall_subnet_id: ::std::option::Option<::std::string::String>,
    /// <p>The firewall subnet routes that are expected.</p>
    pub expected_firewall_subnet_routes: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>,
    /// <p>The actual firewall subnet routes.</p>
    pub actual_firewall_subnet_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    /// <p>The internet gateway ID.</p>
    pub internet_gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The current route table for the internet gateway.</p>
    pub current_internet_gateway_route_table: ::std::option::Option<::std::string::String>,
    /// <p>The internet gateway routes that are expected.</p>
    pub expected_internet_gateway_routes: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>,
    /// <p>The actual internet gateway routes.</p>
    pub actual_internet_gateway_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    /// <p>Information about the VPC ID.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
}
impl NetworkFirewallInternetTrafficNotInspectedViolation {
    /// <p>The subnet ID.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
    /// <p>The subnet Availability Zone.</p>
    pub fn subnet_availability_zone(&self) -> ::std::option::Option<&str> {
        self.subnet_availability_zone.as_deref()
    }
    /// <p>Information about the route table ID.</p>
    pub fn route_table_id(&self) -> ::std::option::Option<&str> {
        self.route_table_id.as_deref()
    }
    /// <p>The route or routes that are in violation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.violating_routes.is_none()`.
    pub fn violating_routes(&self) -> &[crate::types::Route] {
        self.violating_routes.as_deref().unwrap_or_default()
    }
    /// <p>Information about whether the route table is used in another Availability Zone.</p>
    pub fn is_route_table_used_in_different_az(&self) -> bool {
        self.is_route_table_used_in_different_az
    }
    /// <p>Information about the subnet route table for the current firewall.</p>
    pub fn current_firewall_subnet_route_table(&self) -> ::std::option::Option<&str> {
        self.current_firewall_subnet_route_table.as_deref()
    }
    /// <p>The expected endpoint for the current firewall.</p>
    pub fn expected_firewall_endpoint(&self) -> ::std::option::Option<&str> {
        self.expected_firewall_endpoint.as_deref()
    }
    /// <p>The firewall subnet ID.</p>
    pub fn firewall_subnet_id(&self) -> ::std::option::Option<&str> {
        self.firewall_subnet_id.as_deref()
    }
    /// <p>The firewall subnet routes that are expected.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.expected_firewall_subnet_routes.is_none()`.
    pub fn expected_firewall_subnet_routes(&self) -> &[crate::types::ExpectedRoute] {
        self.expected_firewall_subnet_routes.as_deref().unwrap_or_default()
    }
    /// <p>The actual firewall subnet routes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actual_firewall_subnet_routes.is_none()`.
    pub fn actual_firewall_subnet_routes(&self) -> &[crate::types::Route] {
        self.actual_firewall_subnet_routes.as_deref().unwrap_or_default()
    }
    /// <p>The internet gateway ID.</p>
    pub fn internet_gateway_id(&self) -> ::std::option::Option<&str> {
        self.internet_gateway_id.as_deref()
    }
    /// <p>The current route table for the internet gateway.</p>
    pub fn current_internet_gateway_route_table(&self) -> ::std::option::Option<&str> {
        self.current_internet_gateway_route_table.as_deref()
    }
    /// <p>The internet gateway routes that are expected.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.expected_internet_gateway_routes.is_none()`.
    pub fn expected_internet_gateway_routes(&self) -> &[crate::types::ExpectedRoute] {
        self.expected_internet_gateway_routes.as_deref().unwrap_or_default()
    }
    /// <p>The actual internet gateway routes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actual_internet_gateway_routes.is_none()`.
    pub fn actual_internet_gateway_routes(&self) -> &[crate::types::Route] {
        self.actual_internet_gateway_routes.as_deref().unwrap_or_default()
    }
    /// <p>Information about the VPC ID.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
}
impl NetworkFirewallInternetTrafficNotInspectedViolation {
    /// Creates a new builder-style object to manufacture [`NetworkFirewallInternetTrafficNotInspectedViolation`](crate::types::NetworkFirewallInternetTrafficNotInspectedViolation).
    pub fn builder() -> crate::types::builders::NetworkFirewallInternetTrafficNotInspectedViolationBuilder {
        crate::types::builders::NetworkFirewallInternetTrafficNotInspectedViolationBuilder::default()
    }
}

/// A builder for [`NetworkFirewallInternetTrafficNotInspectedViolation`](crate::types::NetworkFirewallInternetTrafficNotInspectedViolation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkFirewallInternetTrafficNotInspectedViolationBuilder {
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) route_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) violating_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    pub(crate) is_route_table_used_in_different_az: ::std::option::Option<bool>,
    pub(crate) current_firewall_subnet_route_table: ::std::option::Option<::std::string::String>,
    pub(crate) expected_firewall_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) firewall_subnet_id: ::std::option::Option<::std::string::String>,
    pub(crate) expected_firewall_subnet_routes: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>,
    pub(crate) actual_firewall_subnet_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    pub(crate) internet_gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) current_internet_gateway_route_table: ::std::option::Option<::std::string::String>,
    pub(crate) expected_internet_gateway_routes: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>,
    pub(crate) actual_internet_gateway_routes: ::std::option::Option<::std::vec::Vec<crate::types::Route>>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
}
impl NetworkFirewallInternetTrafficNotInspectedViolationBuilder {
    /// <p>The subnet ID.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subnet ID.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The subnet ID.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// <p>The subnet Availability Zone.</p>
    pub fn subnet_availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subnet Availability Zone.</p>
    pub fn set_subnet_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_availability_zone = input;
        self
    }
    /// <p>The subnet Availability Zone.</p>
    pub fn get_subnet_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_availability_zone
    }
    /// <p>Information about the route table ID.</p>
    pub fn route_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the route table ID.</p>
    pub fn set_route_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_table_id = input;
        self
    }
    /// <p>Information about the route table ID.</p>
    pub fn get_route_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_table_id
    }
    /// Appends an item to `violating_routes`.
    ///
    /// To override the contents of this collection use [`set_violating_routes`](Self::set_violating_routes).
    ///
    /// <p>The route or routes that are in violation.</p>
    pub fn violating_routes(mut self, input: crate::types::Route) -> Self {
        let mut v = self.violating_routes.unwrap_or_default();
        v.push(input);
        self.violating_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The route or routes that are in violation.</p>
    pub fn set_violating_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Route>>) -> Self {
        self.violating_routes = input;
        self
    }
    /// <p>The route or routes that are in violation.</p>
    pub fn get_violating_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Route>> {
        &self.violating_routes
    }
    /// <p>Information about whether the route table is used in another Availability Zone.</p>
    pub fn is_route_table_used_in_different_az(mut self, input: bool) -> Self {
        self.is_route_table_used_in_different_az = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about whether the route table is used in another Availability Zone.</p>
    pub fn set_is_route_table_used_in_different_az(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_route_table_used_in_different_az = input;
        self
    }
    /// <p>Information about whether the route table is used in another Availability Zone.</p>
    pub fn get_is_route_table_used_in_different_az(&self) -> &::std::option::Option<bool> {
        &self.is_route_table_used_in_different_az
    }
    /// <p>Information about the subnet route table for the current firewall.</p>
    pub fn current_firewall_subnet_route_table(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_firewall_subnet_route_table = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the subnet route table for the current firewall.</p>
    pub fn set_current_firewall_subnet_route_table(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_firewall_subnet_route_table = input;
        self
    }
    /// <p>Information about the subnet route table for the current firewall.</p>
    pub fn get_current_firewall_subnet_route_table(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_firewall_subnet_route_table
    }
    /// <p>The expected endpoint for the current firewall.</p>
    pub fn expected_firewall_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_firewall_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The expected endpoint for the current firewall.</p>
    pub fn set_expected_firewall_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_firewall_endpoint = input;
        self
    }
    /// <p>The expected endpoint for the current firewall.</p>
    pub fn get_expected_firewall_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_firewall_endpoint
    }
    /// <p>The firewall subnet ID.</p>
    pub fn firewall_subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.firewall_subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The firewall subnet ID.</p>
    pub fn set_firewall_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.firewall_subnet_id = input;
        self
    }
    /// <p>The firewall subnet ID.</p>
    pub fn get_firewall_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.firewall_subnet_id
    }
    /// Appends an item to `expected_firewall_subnet_routes`.
    ///
    /// To override the contents of this collection use [`set_expected_firewall_subnet_routes`](Self::set_expected_firewall_subnet_routes).
    ///
    /// <p>The firewall subnet routes that are expected.</p>
    pub fn expected_firewall_subnet_routes(mut self, input: crate::types::ExpectedRoute) -> Self {
        let mut v = self.expected_firewall_subnet_routes.unwrap_or_default();
        v.push(input);
        self.expected_firewall_subnet_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The firewall subnet routes that are expected.</p>
    pub fn set_expected_firewall_subnet_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>) -> Self {
        self.expected_firewall_subnet_routes = input;
        self
    }
    /// <p>The firewall subnet routes that are expected.</p>
    pub fn get_expected_firewall_subnet_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>> {
        &self.expected_firewall_subnet_routes
    }
    /// Appends an item to `actual_firewall_subnet_routes`.
    ///
    /// To override the contents of this collection use [`set_actual_firewall_subnet_routes`](Self::set_actual_firewall_subnet_routes).
    ///
    /// <p>The actual firewall subnet routes.</p>
    pub fn actual_firewall_subnet_routes(mut self, input: crate::types::Route) -> Self {
        let mut v = self.actual_firewall_subnet_routes.unwrap_or_default();
        v.push(input);
        self.actual_firewall_subnet_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The actual firewall subnet routes.</p>
    pub fn set_actual_firewall_subnet_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Route>>) -> Self {
        self.actual_firewall_subnet_routes = input;
        self
    }
    /// <p>The actual firewall subnet routes.</p>
    pub fn get_actual_firewall_subnet_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Route>> {
        &self.actual_firewall_subnet_routes
    }
    /// <p>The internet gateway ID.</p>
    pub fn internet_gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.internet_gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The internet gateway ID.</p>
    pub fn set_internet_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.internet_gateway_id = input;
        self
    }
    /// <p>The internet gateway ID.</p>
    pub fn get_internet_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.internet_gateway_id
    }
    /// <p>The current route table for the internet gateway.</p>
    pub fn current_internet_gateway_route_table(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_internet_gateway_route_table = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current route table for the internet gateway.</p>
    pub fn set_current_internet_gateway_route_table(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_internet_gateway_route_table = input;
        self
    }
    /// <p>The current route table for the internet gateway.</p>
    pub fn get_current_internet_gateway_route_table(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_internet_gateway_route_table
    }
    /// Appends an item to `expected_internet_gateway_routes`.
    ///
    /// To override the contents of this collection use [`set_expected_internet_gateway_routes`](Self::set_expected_internet_gateway_routes).
    ///
    /// <p>The internet gateway routes that are expected.</p>
    pub fn expected_internet_gateway_routes(mut self, input: crate::types::ExpectedRoute) -> Self {
        let mut v = self.expected_internet_gateway_routes.unwrap_or_default();
        v.push(input);
        self.expected_internet_gateway_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The internet gateway routes that are expected.</p>
    pub fn set_expected_internet_gateway_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>>) -> Self {
        self.expected_internet_gateway_routes = input;
        self
    }
    /// <p>The internet gateway routes that are expected.</p>
    pub fn get_expected_internet_gateway_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExpectedRoute>> {
        &self.expected_internet_gateway_routes
    }
    /// Appends an item to `actual_internet_gateway_routes`.
    ///
    /// To override the contents of this collection use [`set_actual_internet_gateway_routes`](Self::set_actual_internet_gateway_routes).
    ///
    /// <p>The actual internet gateway routes.</p>
    pub fn actual_internet_gateway_routes(mut self, input: crate::types::Route) -> Self {
        let mut v = self.actual_internet_gateway_routes.unwrap_or_default();
        v.push(input);
        self.actual_internet_gateway_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The actual internet gateway routes.</p>
    pub fn set_actual_internet_gateway_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Route>>) -> Self {
        self.actual_internet_gateway_routes = input;
        self
    }
    /// <p>The actual internet gateway routes.</p>
    pub fn get_actual_internet_gateway_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Route>> {
        &self.actual_internet_gateway_routes
    }
    /// <p>Information about the VPC ID.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the VPC ID.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>Information about the VPC ID.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Consumes the builder and constructs a [`NetworkFirewallInternetTrafficNotInspectedViolation`](crate::types::NetworkFirewallInternetTrafficNotInspectedViolation).
    pub fn build(self) -> crate::types::NetworkFirewallInternetTrafficNotInspectedViolation {
        crate::types::NetworkFirewallInternetTrafficNotInspectedViolation {
            subnet_id: self.subnet_id,
            subnet_availability_zone: self.subnet_availability_zone,
            route_table_id: self.route_table_id,
            violating_routes: self.violating_routes,
            is_route_table_used_in_different_az: self.is_route_table_used_in_different_az.unwrap_or_default(),
            current_firewall_subnet_route_table: self.current_firewall_subnet_route_table,
            expected_firewall_endpoint: self.expected_firewall_endpoint,
            firewall_subnet_id: self.firewall_subnet_id,
            expected_firewall_subnet_routes: self.expected_firewall_subnet_routes,
            actual_firewall_subnet_routes: self.actual_firewall_subnet_routes,
            internet_gateway_id: self.internet_gateway_id,
            current_internet_gateway_route_table: self.current_internet_gateway_route_table,
            expected_internet_gateway_routes: self.expected_internet_gateway_routes,
            actual_internet_gateway_routes: self.actual_internet_gateway_routes,
            vpc_id: self.vpc_id,
        }
    }
}
