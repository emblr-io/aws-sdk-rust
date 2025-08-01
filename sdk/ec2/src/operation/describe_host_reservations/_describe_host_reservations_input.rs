// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeHostReservationsInput {
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-family</code> - The instance family (for example, <code>m4</code>).</p></li>
    /// <li>
    /// <p><code>payment-option</code> - The payment option (<code>NoUpfront</code> | <code>PartialUpfront</code> | <code>AllUpfront</code>).</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the reservation (<code>payment-pending</code> | <code>payment-failed</code> | <code>active</code> | <code>retired</code>).</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub filter: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The host reservation IDs.</p>
    pub host_reservation_id_set: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The maximum number of results to return for the request in a single page. The remaining results can be seen by sending another request with the returned <code>nextToken</code> value. This value can be between 5 and 500. If <code>maxResults</code> is given a larger value than 500, you receive an error.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token to use to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeHostReservationsInput {
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-family</code> - The instance family (for example, <code>m4</code>).</p></li>
    /// <li>
    /// <p><code>payment-option</code> - The payment option (<code>NoUpfront</code> | <code>PartialUpfront</code> | <code>AllUpfront</code>).</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the reservation (<code>payment-pending</code> | <code>payment-failed</code> | <code>active</code> | <code>retired</code>).</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter.is_none()`.
    pub fn filter(&self) -> &[crate::types::Filter] {
        self.filter.as_deref().unwrap_or_default()
    }
    /// <p>The host reservation IDs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.host_reservation_id_set.is_none()`.
    pub fn host_reservation_id_set(&self) -> &[::std::string::String] {
        self.host_reservation_id_set.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results can be seen by sending another request with the returned <code>nextToken</code> value. This value can be between 5 and 500. If <code>maxResults</code> is given a larger value than 500, you receive an error.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token to use to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeHostReservationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeHostReservationsInput`](crate::operation::describe_host_reservations::DescribeHostReservationsInput).
    pub fn builder() -> crate::operation::describe_host_reservations::builders::DescribeHostReservationsInputBuilder {
        crate::operation::describe_host_reservations::builders::DescribeHostReservationsInputBuilder::default()
    }
}

/// A builder for [`DescribeHostReservationsInput`](crate::operation::describe_host_reservations::DescribeHostReservationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeHostReservationsInputBuilder {
    pub(crate) filter: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) host_reservation_id_set: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeHostReservationsInputBuilder {
    /// Appends an item to `filter`.
    ///
    /// To override the contents of this collection use [`set_filter`](Self::set_filter).
    ///
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-family</code> - The instance family (for example, <code>m4</code>).</p></li>
    /// <li>
    /// <p><code>payment-option</code> - The payment option (<code>NoUpfront</code> | <code>PartialUpfront</code> | <code>AllUpfront</code>).</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the reservation (<code>payment-pending</code> | <code>payment-failed</code> | <code>active</code> | <code>retired</code>).</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn filter(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filter.unwrap_or_default();
        v.push(input);
        self.filter = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-family</code> - The instance family (for example, <code>m4</code>).</p></li>
    /// <li>
    /// <p><code>payment-option</code> - The payment option (<code>NoUpfront</code> | <code>PartialUpfront</code> | <code>AllUpfront</code>).</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the reservation (<code>payment-pending</code> | <code>payment-failed</code> | <code>active</code> | <code>retired</code>).</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn set_filter(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filter = input;
        self
    }
    /// <p>The filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>instance-family</code> - The instance family (for example, <code>m4</code>).</p></li>
    /// <li>
    /// <p><code>payment-option</code> - The payment option (<code>NoUpfront</code> | <code>PartialUpfront</code> | <code>AllUpfront</code>).</p></li>
    /// <li>
    /// <p><code>state</code> - The state of the reservation (<code>payment-pending</code> | <code>payment-failed</code> | <code>active</code> | <code>retired</code>).</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// </ul>
    pub fn get_filter(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filter
    }
    /// Appends an item to `host_reservation_id_set`.
    ///
    /// To override the contents of this collection use [`set_host_reservation_id_set`](Self::set_host_reservation_id_set).
    ///
    /// <p>The host reservation IDs.</p>
    pub fn host_reservation_id_set(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.host_reservation_id_set.unwrap_or_default();
        v.push(input.into());
        self.host_reservation_id_set = ::std::option::Option::Some(v);
        self
    }
    /// <p>The host reservation IDs.</p>
    pub fn set_host_reservation_id_set(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.host_reservation_id_set = input;
        self
    }
    /// <p>The host reservation IDs.</p>
    pub fn get_host_reservation_id_set(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.host_reservation_id_set
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results can be seen by sending another request with the returned <code>nextToken</code> value. This value can be between 5 and 500. If <code>maxResults</code> is given a larger value than 500, you receive an error.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results can be seen by sending another request with the returned <code>nextToken</code> value. This value can be between 5 and 500. If <code>maxResults</code> is given a larger value than 500, you receive an error.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results can be seen by sending another request with the returned <code>nextToken</code> value. This value can be between 5 and 500. If <code>maxResults</code> is given a larger value than 500, you receive an error.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
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
    /// Consumes the builder and constructs a [`DescribeHostReservationsInput`](crate::operation::describe_host_reservations::DescribeHostReservationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_host_reservations::DescribeHostReservationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_host_reservations::DescribeHostReservationsInput {
            filter: self.filter,
            host_reservation_id_set: self.host_reservation_id_set,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
