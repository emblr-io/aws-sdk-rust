// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAggregateDiscoveredResourceCountsOutput {
    /// <p>The total number of resources that are present in an aggregator with the filters that you provide.</p>
    pub total_discovered_resources: i64,
    /// <p>The key passed into the request object. If <code>GroupByKey</code> is not provided, the result will be empty.</p>
    pub group_by_key: ::std::option::Option<::std::string::String>,
    /// <p>Returns a list of GroupedResourceCount objects.</p>
    pub grouped_resource_counts: ::std::option::Option<::std::vec::Vec<crate::types::GroupedResourceCount>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAggregateDiscoveredResourceCountsOutput {
    /// <p>The total number of resources that are present in an aggregator with the filters that you provide.</p>
    pub fn total_discovered_resources(&self) -> i64 {
        self.total_discovered_resources
    }
    /// <p>The key passed into the request object. If <code>GroupByKey</code> is not provided, the result will be empty.</p>
    pub fn group_by_key(&self) -> ::std::option::Option<&str> {
        self.group_by_key.as_deref()
    }
    /// <p>Returns a list of GroupedResourceCount objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.grouped_resource_counts.is_none()`.
    pub fn grouped_resource_counts(&self) -> &[crate::types::GroupedResourceCount] {
        self.grouped_resource_counts.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetAggregateDiscoveredResourceCountsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAggregateDiscoveredResourceCountsOutput {
    /// Creates a new builder-style object to manufacture [`GetAggregateDiscoveredResourceCountsOutput`](crate::operation::get_aggregate_discovered_resource_counts::GetAggregateDiscoveredResourceCountsOutput).
    pub fn builder() -> crate::operation::get_aggregate_discovered_resource_counts::builders::GetAggregateDiscoveredResourceCountsOutputBuilder {
        crate::operation::get_aggregate_discovered_resource_counts::builders::GetAggregateDiscoveredResourceCountsOutputBuilder::default()
    }
}

/// A builder for [`GetAggregateDiscoveredResourceCountsOutput`](crate::operation::get_aggregate_discovered_resource_counts::GetAggregateDiscoveredResourceCountsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAggregateDiscoveredResourceCountsOutputBuilder {
    pub(crate) total_discovered_resources: ::std::option::Option<i64>,
    pub(crate) group_by_key: ::std::option::Option<::std::string::String>,
    pub(crate) grouped_resource_counts: ::std::option::Option<::std::vec::Vec<crate::types::GroupedResourceCount>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAggregateDiscoveredResourceCountsOutputBuilder {
    /// <p>The total number of resources that are present in an aggregator with the filters that you provide.</p>
    /// This field is required.
    pub fn total_discovered_resources(mut self, input: i64) -> Self {
        self.total_discovered_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources that are present in an aggregator with the filters that you provide.</p>
    pub fn set_total_discovered_resources(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_discovered_resources = input;
        self
    }
    /// <p>The total number of resources that are present in an aggregator with the filters that you provide.</p>
    pub fn get_total_discovered_resources(&self) -> &::std::option::Option<i64> {
        &self.total_discovered_resources
    }
    /// <p>The key passed into the request object. If <code>GroupByKey</code> is not provided, the result will be empty.</p>
    pub fn group_by_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_by_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key passed into the request object. If <code>GroupByKey</code> is not provided, the result will be empty.</p>
    pub fn set_group_by_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_by_key = input;
        self
    }
    /// <p>The key passed into the request object. If <code>GroupByKey</code> is not provided, the result will be empty.</p>
    pub fn get_group_by_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_by_key
    }
    /// Appends an item to `grouped_resource_counts`.
    ///
    /// To override the contents of this collection use [`set_grouped_resource_counts`](Self::set_grouped_resource_counts).
    ///
    /// <p>Returns a list of GroupedResourceCount objects.</p>
    pub fn grouped_resource_counts(mut self, input: crate::types::GroupedResourceCount) -> Self {
        let mut v = self.grouped_resource_counts.unwrap_or_default();
        v.push(input);
        self.grouped_resource_counts = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns a list of GroupedResourceCount objects.</p>
    pub fn set_grouped_resource_counts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupedResourceCount>>) -> Self {
        self.grouped_resource_counts = input;
        self
    }
    /// <p>Returns a list of GroupedResourceCount objects.</p>
    pub fn get_grouped_resource_counts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupedResourceCount>> {
        &self.grouped_resource_counts
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
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
    /// Consumes the builder and constructs a [`GetAggregateDiscoveredResourceCountsOutput`](crate::operation::get_aggregate_discovered_resource_counts::GetAggregateDiscoveredResourceCountsOutput).
    pub fn build(self) -> crate::operation::get_aggregate_discovered_resource_counts::GetAggregateDiscoveredResourceCountsOutput {
        crate::operation::get_aggregate_discovered_resource_counts::GetAggregateDiscoveredResourceCountsOutput {
            total_discovered_resources: self.total_discovered_resources.unwrap_or_default(),
            group_by_key: self.group_by_key,
            grouped_resource_counts: self.grouped_resource_counts,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
