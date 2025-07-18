// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCapacityReservationFleetsInput {
    /// <p>The IDs of the Capacity Reservation Fleets to describe.</p>
    pub capacity_reservation_fleet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The token to use to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the Fleet (<code>submitted</code> | <code>modifying</code> | <code>active</code> | <code>partially_fulfilled</code> | <code>expiring</code> | <code>expired</code> | <code>cancelling</code> | <code>cancelled</code> | <code>failed</code>).</p></li>
    /// <li>
    /// <p><code>instance-match-criteria</code> - The instance matching criteria for the Fleet. Only <code>open</code> is supported.</p></li>
    /// <li>
    /// <p><code>tenancy</code> - The tenancy of the Fleet (<code>default</code> | <code>dedicated</code>).</p></li>
    /// <li>
    /// <p><code>allocation-strategy</code> - The allocation strategy used by the Fleet. Only <code>prioritized</code> is supported.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DescribeCapacityReservationFleetsInput {
    /// <p>The IDs of the Capacity Reservation Fleets to describe.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capacity_reservation_fleet_ids.is_none()`.
    pub fn capacity_reservation_fleet_ids(&self) -> &[::std::string::String] {
        self.capacity_reservation_fleet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the Fleet (<code>submitted</code> | <code>modifying</code> | <code>active</code> | <code>partially_fulfilled</code> | <code>expiring</code> | <code>expired</code> | <code>cancelling</code> | <code>cancelled</code> | <code>failed</code>).</p></li>
    /// <li>
    /// <p><code>instance-match-criteria</code> - The instance matching criteria for the Fleet. Only <code>open</code> is supported.</p></li>
    /// <li>
    /// <p><code>tenancy</code> - The tenancy of the Fleet (<code>default</code> | <code>dedicated</code>).</p></li>
    /// <li>
    /// <p><code>allocation-strategy</code> - The allocation strategy used by the Fleet. Only <code>prioritized</code> is supported.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DescribeCapacityReservationFleetsInput {
    /// Creates a new builder-style object to manufacture [`DescribeCapacityReservationFleetsInput`](crate::operation::describe_capacity_reservation_fleets::DescribeCapacityReservationFleetsInput).
    pub fn builder() -> crate::operation::describe_capacity_reservation_fleets::builders::DescribeCapacityReservationFleetsInputBuilder {
        crate::operation::describe_capacity_reservation_fleets::builders::DescribeCapacityReservationFleetsInputBuilder::default()
    }
}

/// A builder for [`DescribeCapacityReservationFleetsInput`](crate::operation::describe_capacity_reservation_fleets::DescribeCapacityReservationFleetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCapacityReservationFleetsInputBuilder {
    pub(crate) capacity_reservation_fleet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DescribeCapacityReservationFleetsInputBuilder {
    /// Appends an item to `capacity_reservation_fleet_ids`.
    ///
    /// To override the contents of this collection use [`set_capacity_reservation_fleet_ids`](Self::set_capacity_reservation_fleet_ids).
    ///
    /// <p>The IDs of the Capacity Reservation Fleets to describe.</p>
    pub fn capacity_reservation_fleet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.capacity_reservation_fleet_ids.unwrap_or_default();
        v.push(input.into());
        self.capacity_reservation_fleet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Capacity Reservation Fleets to describe.</p>
    pub fn set_capacity_reservation_fleet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.capacity_reservation_fleet_ids = input;
        self
    }
    /// <p>The IDs of the Capacity Reservation Fleets to describe.</p>
    pub fn get_capacity_reservation_fleet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.capacity_reservation_fleet_ids
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the Fleet (<code>submitted</code> | <code>modifying</code> | <code>active</code> | <code>partially_fulfilled</code> | <code>expiring</code> | <code>expired</code> | <code>cancelling</code> | <code>cancelled</code> | <code>failed</code>).</p></li>
    /// <li>
    /// <p><code>instance-match-criteria</code> - The instance matching criteria for the Fleet. Only <code>open</code> is supported.</p></li>
    /// <li>
    /// <p><code>tenancy</code> - The tenancy of the Fleet (<code>default</code> | <code>dedicated</code>).</p></li>
    /// <li>
    /// <p><code>allocation-strategy</code> - The allocation strategy used by the Fleet. Only <code>prioritized</code> is supported.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the Fleet (<code>submitted</code> | <code>modifying</code> | <code>active</code> | <code>partially_fulfilled</code> | <code>expiring</code> | <code>expired</code> | <code>cancelling</code> | <code>cancelled</code> | <code>failed</code>).</p></li>
    /// <li>
    /// <p><code>instance-match-criteria</code> - The instance matching criteria for the Fleet. Only <code>open</code> is supported.</p></li>
    /// <li>
    /// <p><code>tenancy</code> - The tenancy of the Fleet (<code>default</code> | <code>dedicated</code>).</p></li>
    /// <li>
    /// <p><code>allocation-strategy</code> - The allocation strategy used by the Fleet. Only <code>prioritized</code> is supported.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>state</code> - The state of the Fleet (<code>submitted</code> | <code>modifying</code> | <code>active</code> | <code>partially_fulfilled</code> | <code>expiring</code> | <code>expired</code> | <code>cancelling</code> | <code>cancelled</code> | <code>failed</code>).</p></li>
    /// <li>
    /// <p><code>instance-match-criteria</code> - The instance matching criteria for the Fleet. Only <code>open</code> is supported.</p></li>
    /// <li>
    /// <p><code>tenancy</code> - The tenancy of the Fleet (<code>default</code> | <code>dedicated</code>).</p></li>
    /// <li>
    /// <p><code>allocation-strategy</code> - The allocation strategy used by the Fleet. Only <code>prioritized</code> is supported.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
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
    /// Consumes the builder and constructs a [`DescribeCapacityReservationFleetsInput`](crate::operation::describe_capacity_reservation_fleets::DescribeCapacityReservationFleetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_capacity_reservation_fleets::DescribeCapacityReservationFleetsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_capacity_reservation_fleets::DescribeCapacityReservationFleetsInput {
                capacity_reservation_fleet_ids: self.capacity_reservation_fleet_ids,
                next_token: self.next_token,
                max_results: self.max_results,
                filters: self.filters,
                dry_run: self.dry_run,
            },
        )
    }
}
