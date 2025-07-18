// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSubnetCidrReservationsOutput {
    /// <p>Information about the IPv4 subnet CIDR reservations.</p>
    pub subnet_ipv4_cidr_reservations: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>,
    /// <p>Information about the IPv6 subnet CIDR reservations.</p>
    pub subnet_ipv6_cidr_reservations: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSubnetCidrReservationsOutput {
    /// <p>Information about the IPv4 subnet CIDR reservations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ipv4_cidr_reservations.is_none()`.
    pub fn subnet_ipv4_cidr_reservations(&self) -> &[crate::types::SubnetCidrReservation] {
        self.subnet_ipv4_cidr_reservations.as_deref().unwrap_or_default()
    }
    /// <p>Information about the IPv6 subnet CIDR reservations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ipv6_cidr_reservations.is_none()`.
    pub fn subnet_ipv6_cidr_reservations(&self) -> &[crate::types::SubnetCidrReservation] {
        self.subnet_ipv6_cidr_reservations.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetSubnetCidrReservationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSubnetCidrReservationsOutput {
    /// Creates a new builder-style object to manufacture [`GetSubnetCidrReservationsOutput`](crate::operation::get_subnet_cidr_reservations::GetSubnetCidrReservationsOutput).
    pub fn builder() -> crate::operation::get_subnet_cidr_reservations::builders::GetSubnetCidrReservationsOutputBuilder {
        crate::operation::get_subnet_cidr_reservations::builders::GetSubnetCidrReservationsOutputBuilder::default()
    }
}

/// A builder for [`GetSubnetCidrReservationsOutput`](crate::operation::get_subnet_cidr_reservations::GetSubnetCidrReservationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSubnetCidrReservationsOutputBuilder {
    pub(crate) subnet_ipv4_cidr_reservations: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>,
    pub(crate) subnet_ipv6_cidr_reservations: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSubnetCidrReservationsOutputBuilder {
    /// Appends an item to `subnet_ipv4_cidr_reservations`.
    ///
    /// To override the contents of this collection use [`set_subnet_ipv4_cidr_reservations`](Self::set_subnet_ipv4_cidr_reservations).
    ///
    /// <p>Information about the IPv4 subnet CIDR reservations.</p>
    pub fn subnet_ipv4_cidr_reservations(mut self, input: crate::types::SubnetCidrReservation) -> Self {
        let mut v = self.subnet_ipv4_cidr_reservations.unwrap_or_default();
        v.push(input);
        self.subnet_ipv4_cidr_reservations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the IPv4 subnet CIDR reservations.</p>
    pub fn set_subnet_ipv4_cidr_reservations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>) -> Self {
        self.subnet_ipv4_cidr_reservations = input;
        self
    }
    /// <p>Information about the IPv4 subnet CIDR reservations.</p>
    pub fn get_subnet_ipv4_cidr_reservations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>> {
        &self.subnet_ipv4_cidr_reservations
    }
    /// Appends an item to `subnet_ipv6_cidr_reservations`.
    ///
    /// To override the contents of this collection use [`set_subnet_ipv6_cidr_reservations`](Self::set_subnet_ipv6_cidr_reservations).
    ///
    /// <p>Information about the IPv6 subnet CIDR reservations.</p>
    pub fn subnet_ipv6_cidr_reservations(mut self, input: crate::types::SubnetCidrReservation) -> Self {
        let mut v = self.subnet_ipv6_cidr_reservations.unwrap_or_default();
        v.push(input);
        self.subnet_ipv6_cidr_reservations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the IPv6 subnet CIDR reservations.</p>
    pub fn set_subnet_ipv6_cidr_reservations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>>) -> Self {
        self.subnet_ipv6_cidr_reservations = input;
        self
    }
    /// <p>Information about the IPv6 subnet CIDR reservations.</p>
    pub fn get_subnet_ipv6_cidr_reservations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SubnetCidrReservation>> {
        &self.subnet_ipv6_cidr_reservations
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSubnetCidrReservationsOutput`](crate::operation::get_subnet_cidr_reservations::GetSubnetCidrReservationsOutput).
    pub fn build(self) -> crate::operation::get_subnet_cidr_reservations::GetSubnetCidrReservationsOutput {
        crate::operation::get_subnet_cidr_reservations::GetSubnetCidrReservationsOutput {
            subnet_ipv4_cidr_reservations: self.subnet_ipv4_cidr_reservations,
            subnet_ipv6_cidr_reservations: self.subnet_ipv6_cidr_reservations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
