// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describe instance event windows by InstanceEventWindow.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstanceEventWindowsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The IDs of the event windows.</p>
    pub instance_event_window_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>dedicated-host-id</code> - The event windows associated with the specified Dedicated Host ID.</p></li>
    /// <li>
    /// <p><code>event-window-name</code> - The event windows associated with the specified names.</p></li>
    /// <li>
    /// <p><code>instance-id</code> - The event windows associated with the specified instance ID.</p></li>
    /// <li>
    /// <p><code>instance-tag</code> - The event windows associated with the specified tag and value.</p></li>
    /// <li>
    /// <p><code>instance-tag-key</code> - The event windows associated with the specified tag key, regardless of the value.</p></li>
    /// <li>
    /// <p><code>instance-tag-value</code> - The event windows associated with the specified tag value, regardless of the key.</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the event window. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>CMX</code>, specify <code>tag:Owner</code> for the filter name and <code>CMX</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>tag-value</code> - The value of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific value, regardless of the tag key.</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 20 and 500. You cannot specify this parameter and the event window IDs parameter in the same call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token to request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeInstanceEventWindowsInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The IDs of the event windows.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_event_window_ids.is_none()`.
    pub fn instance_event_window_ids(&self) -> &[::std::string::String] {
        self.instance_event_window_ids.as_deref().unwrap_or_default()
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>dedicated-host-id</code> - The event windows associated with the specified Dedicated Host ID.</p></li>
    /// <li>
    /// <p><code>event-window-name</code> - The event windows associated with the specified names.</p></li>
    /// <li>
    /// <p><code>instance-id</code> - The event windows associated with the specified instance ID.</p></li>
    /// <li>
    /// <p><code>instance-tag</code> - The event windows associated with the specified tag and value.</p></li>
    /// <li>
    /// <p><code>instance-tag-key</code> - The event windows associated with the specified tag key, regardless of the value.</p></li>
    /// <li>
    /// <p><code>instance-tag-value</code> - The event windows associated with the specified tag value, regardless of the key.</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the event window. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>CMX</code>, specify <code>tag:Owner</code> for the filter name and <code>CMX</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>tag-value</code> - The value of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific value, regardless of the tag key.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 20 and 500. You cannot specify this parameter and the event window IDs parameter in the same call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeInstanceEventWindowsInput {
    /// Creates a new builder-style object to manufacture [`DescribeInstanceEventWindowsInput`](crate::operation::describe_instance_event_windows::DescribeInstanceEventWindowsInput).
    pub fn builder() -> crate::operation::describe_instance_event_windows::builders::DescribeInstanceEventWindowsInputBuilder {
        crate::operation::describe_instance_event_windows::builders::DescribeInstanceEventWindowsInputBuilder::default()
    }
}

/// A builder for [`DescribeInstanceEventWindowsInput`](crate::operation::describe_instance_event_windows::DescribeInstanceEventWindowsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstanceEventWindowsInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) instance_event_window_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeInstanceEventWindowsInputBuilder {
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
    /// Appends an item to `instance_event_window_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_event_window_ids`](Self::set_instance_event_window_ids).
    ///
    /// <p>The IDs of the event windows.</p>
    pub fn instance_event_window_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_event_window_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_event_window_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the event windows.</p>
    pub fn set_instance_event_window_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_event_window_ids = input;
        self
    }
    /// <p>The IDs of the event windows.</p>
    pub fn get_instance_event_window_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_event_window_ids
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>dedicated-host-id</code> - The event windows associated with the specified Dedicated Host ID.</p></li>
    /// <li>
    /// <p><code>event-window-name</code> - The event windows associated with the specified names.</p></li>
    /// <li>
    /// <p><code>instance-id</code> - The event windows associated with the specified instance ID.</p></li>
    /// <li>
    /// <p><code>instance-tag</code> - The event windows associated with the specified tag and value.</p></li>
    /// <li>
    /// <p><code>instance-tag-key</code> - The event windows associated with the specified tag key, regardless of the value.</p></li>
    /// <li>
    /// <p><code>instance-tag-value</code> - The event windows associated with the specified tag value, regardless of the key.</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the event window. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>CMX</code>, specify <code>tag:Owner</code> for the filter name and <code>CMX</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>tag-value</code> - The value of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific value, regardless of the tag key.</p></li>
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
    /// <p><code>dedicated-host-id</code> - The event windows associated with the specified Dedicated Host ID.</p></li>
    /// <li>
    /// <p><code>event-window-name</code> - The event windows associated with the specified names.</p></li>
    /// <li>
    /// <p><code>instance-id</code> - The event windows associated with the specified instance ID.</p></li>
    /// <li>
    /// <p><code>instance-tag</code> - The event windows associated with the specified tag and value.</p></li>
    /// <li>
    /// <p><code>instance-tag-key</code> - The event windows associated with the specified tag key, regardless of the value.</p></li>
    /// <li>
    /// <p><code>instance-tag-value</code> - The event windows associated with the specified tag value, regardless of the key.</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the event window. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>CMX</code>, specify <code>tag:Owner</code> for the filter name and <code>CMX</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>tag-value</code> - The value of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific value, regardless of the tag key.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>dedicated-host-id</code> - The event windows associated with the specified Dedicated Host ID.</p></li>
    /// <li>
    /// <p><code>event-window-name</code> - The event windows associated with the specified names.</p></li>
    /// <li>
    /// <p><code>instance-id</code> - The event windows associated with the specified instance ID.</p></li>
    /// <li>
    /// <p><code>instance-tag</code> - The event windows associated with the specified tag and value.</p></li>
    /// <li>
    /// <p><code>instance-tag-key</code> - The event windows associated with the specified tag key, regardless of the value.</p></li>
    /// <li>
    /// <p><code>instance-tag-value</code> - The event windows associated with the specified tag value, regardless of the key.</p></li>
    /// <li>
    /// <p><code>tag:<key></key></code> - The key/value combination of a tag assigned to the event window. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key <code>Owner</code> and the value <code>CMX</code>, specify <code>tag:Owner</code> for the filter name and <code>CMX</code> for the filter value.</p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>tag-value</code> - The value of a tag assigned to the event window. Use this filter to find all event windows that have a tag with a specific value, regardless of the tag key.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 20 and 500. You cannot specify this parameter and the event window IDs parameter in the same call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 20 and 500. You cannot specify this parameter and the event window IDs parameter in the same call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call. To retrieve the remaining results, make another call with the returned <code>NextToken</code> value. This value can be between 20 and 500. You cannot specify this parameter and the event window IDs parameter in the same call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token to request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to request the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeInstanceEventWindowsInput`](crate::operation::describe_instance_event_windows::DescribeInstanceEventWindowsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_instance_event_windows::DescribeInstanceEventWindowsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_instance_event_windows::DescribeInstanceEventWindowsInput {
            dry_run: self.dry_run,
            instance_event_window_ids: self.instance_event_window_ids,
            filters: self.filters,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
