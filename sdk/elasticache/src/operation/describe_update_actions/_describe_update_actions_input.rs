// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeUpdateActionsInput {
    /// <p>The unique ID of the service update</p>
    pub service_update_name: ::std::option::Option<::std::string::String>,
    /// <p>The replication group IDs</p>
    pub replication_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The cache cluster IDs</p>
    pub cache_cluster_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub engine: ::std::option::Option<::std::string::String>,
    /// <p>The status of the service update</p>
    pub service_update_status: ::std::option::Option<::std::vec::Vec<crate::types::ServiceUpdateStatus>>,
    /// <p>The range of time specified to search for service updates that are in available status</p>
    pub service_update_time_range: ::std::option::Option<crate::types::TimeRangeFilter>,
    /// <p>The status of the update action.</p>
    pub update_action_status: ::std::option::Option<::std::vec::Vec<crate::types::UpdateActionStatus>>,
    /// <p>Dictates whether to include node level update status in the response</p>
    pub show_node_level_update_status: ::std::option::Option<bool>,
    /// <p>The maximum number of records to include in the response</p>
    pub max_records: ::std::option::Option<i32>,
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl DescribeUpdateActionsInput {
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(&self) -> ::std::option::Option<&str> {
        self.service_update_name.as_deref()
    }
    /// <p>The replication group IDs</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_group_ids.is_none()`.
    pub fn replication_group_ids(&self) -> &[::std::string::String] {
        self.replication_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The cache cluster IDs</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cache_cluster_ids.is_none()`.
    pub fn cache_cluster_ids(&self) -> &[::std::string::String] {
        self.cache_cluster_ids.as_deref().unwrap_or_default()
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn engine(&self) -> ::std::option::Option<&str> {
        self.engine.as_deref()
    }
    /// <p>The status of the service update</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_update_status.is_none()`.
    pub fn service_update_status(&self) -> &[crate::types::ServiceUpdateStatus] {
        self.service_update_status.as_deref().unwrap_or_default()
    }
    /// <p>The range of time specified to search for service updates that are in available status</p>
    pub fn service_update_time_range(&self) -> ::std::option::Option<&crate::types::TimeRangeFilter> {
        self.service_update_time_range.as_ref()
    }
    /// <p>The status of the update action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.update_action_status.is_none()`.
    pub fn update_action_status(&self) -> &[crate::types::UpdateActionStatus] {
        self.update_action_status.as_deref().unwrap_or_default()
    }
    /// <p>Dictates whether to include node level update status in the response</p>
    pub fn show_node_level_update_status(&self) -> ::std::option::Option<bool> {
        self.show_node_level_update_status
    }
    /// <p>The maximum number of records to include in the response</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl DescribeUpdateActionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeUpdateActionsInput`](crate::operation::describe_update_actions::DescribeUpdateActionsInput).
    pub fn builder() -> crate::operation::describe_update_actions::builders::DescribeUpdateActionsInputBuilder {
        crate::operation::describe_update_actions::builders::DescribeUpdateActionsInputBuilder::default()
    }
}

/// A builder for [`DescribeUpdateActionsInput`](crate::operation::describe_update_actions::DescribeUpdateActionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeUpdateActionsInputBuilder {
    pub(crate) service_update_name: ::std::option::Option<::std::string::String>,
    pub(crate) replication_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) cache_cluster_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) engine: ::std::option::Option<::std::string::String>,
    pub(crate) service_update_status: ::std::option::Option<::std::vec::Vec<crate::types::ServiceUpdateStatus>>,
    pub(crate) service_update_time_range: ::std::option::Option<crate::types::TimeRangeFilter>,
    pub(crate) update_action_status: ::std::option::Option<::std::vec::Vec<crate::types::UpdateActionStatus>>,
    pub(crate) show_node_level_update_status: ::std::option::Option<bool>,
    pub(crate) max_records: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl DescribeUpdateActionsInputBuilder {
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_update_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn set_service_update_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_update_name = input;
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn get_service_update_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_update_name
    }
    /// Appends an item to `replication_group_ids`.
    ///
    /// To override the contents of this collection use [`set_replication_group_ids`](Self::set_replication_group_ids).
    ///
    /// <p>The replication group IDs</p>
    pub fn replication_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.replication_group_ids.unwrap_or_default();
        v.push(input.into());
        self.replication_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The replication group IDs</p>
    pub fn set_replication_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.replication_group_ids = input;
        self
    }
    /// <p>The replication group IDs</p>
    pub fn get_replication_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.replication_group_ids
    }
    /// Appends an item to `cache_cluster_ids`.
    ///
    /// To override the contents of this collection use [`set_cache_cluster_ids`](Self::set_cache_cluster_ids).
    ///
    /// <p>The cache cluster IDs</p>
    pub fn cache_cluster_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.cache_cluster_ids.unwrap_or_default();
        v.push(input.into());
        self.cache_cluster_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The cache cluster IDs</p>
    pub fn set_cache_cluster_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.cache_cluster_ids = input;
        self
    }
    /// <p>The cache cluster IDs</p>
    pub fn get_cache_cluster_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.cache_cluster_ids
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn engine(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn set_engine(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine = input;
        self
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn get_engine(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine
    }
    /// Appends an item to `service_update_status`.
    ///
    /// To override the contents of this collection use [`set_service_update_status`](Self::set_service_update_status).
    ///
    /// <p>The status of the service update</p>
    pub fn service_update_status(mut self, input: crate::types::ServiceUpdateStatus) -> Self {
        let mut v = self.service_update_status.unwrap_or_default();
        v.push(input);
        self.service_update_status = ::std::option::Option::Some(v);
        self
    }
    /// <p>The status of the service update</p>
    pub fn set_service_update_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceUpdateStatus>>) -> Self {
        self.service_update_status = input;
        self
    }
    /// <p>The status of the service update</p>
    pub fn get_service_update_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceUpdateStatus>> {
        &self.service_update_status
    }
    /// <p>The range of time specified to search for service updates that are in available status</p>
    pub fn service_update_time_range(mut self, input: crate::types::TimeRangeFilter) -> Self {
        self.service_update_time_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The range of time specified to search for service updates that are in available status</p>
    pub fn set_service_update_time_range(mut self, input: ::std::option::Option<crate::types::TimeRangeFilter>) -> Self {
        self.service_update_time_range = input;
        self
    }
    /// <p>The range of time specified to search for service updates that are in available status</p>
    pub fn get_service_update_time_range(&self) -> &::std::option::Option<crate::types::TimeRangeFilter> {
        &self.service_update_time_range
    }
    /// Appends an item to `update_action_status`.
    ///
    /// To override the contents of this collection use [`set_update_action_status`](Self::set_update_action_status).
    ///
    /// <p>The status of the update action.</p>
    pub fn update_action_status(mut self, input: crate::types::UpdateActionStatus) -> Self {
        let mut v = self.update_action_status.unwrap_or_default();
        v.push(input);
        self.update_action_status = ::std::option::Option::Some(v);
        self
    }
    /// <p>The status of the update action.</p>
    pub fn set_update_action_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateActionStatus>>) -> Self {
        self.update_action_status = input;
        self
    }
    /// <p>The status of the update action.</p>
    pub fn get_update_action_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateActionStatus>> {
        &self.update_action_status
    }
    /// <p>Dictates whether to include node level update status in the response</p>
    pub fn show_node_level_update_status(mut self, input: bool) -> Self {
        self.show_node_level_update_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Dictates whether to include node level update status in the response</p>
    pub fn set_show_node_level_update_status(mut self, input: ::std::option::Option<bool>) -> Self {
        self.show_node_level_update_status = input;
        self
    }
    /// <p>Dictates whether to include node level update status in the response</p>
    pub fn get_show_node_level_update_status(&self) -> &::std::option::Option<bool> {
        &self.show_node_level_update_status
    }
    /// <p>The maximum number of records to include in the response</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of records to include in the response</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number of records to include in the response</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional marker returned from a prior request. Use this marker for pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`DescribeUpdateActionsInput`](crate::operation::describe_update_actions::DescribeUpdateActionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_update_actions::DescribeUpdateActionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_update_actions::DescribeUpdateActionsInput {
            service_update_name: self.service_update_name,
            replication_group_ids: self.replication_group_ids,
            cache_cluster_ids: self.cache_cluster_ids,
            engine: self.engine,
            service_update_status: self.service_update_status,
            service_update_time_range: self.service_update_time_range,
            update_action_status: self.update_action_status,
            show_node_level_update_status: self.show_node_level_update_status,
            max_records: self.max_records,
            marker: self.marker,
        })
    }
}
