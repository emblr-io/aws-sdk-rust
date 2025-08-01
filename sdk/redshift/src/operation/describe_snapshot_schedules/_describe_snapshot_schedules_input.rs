// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSnapshotSchedulesInput {
    /// <p>The unique identifier for the cluster whose snapshot schedules you want to view.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for a snapshot schedule.</p>
    pub schedule_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The key value for a snapshot schedule tag.</p>
    pub tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The value corresponding to the key of the snapshot schedule tag.</p>
    pub tag_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>marker</code> parameter and retrying the command. If the <code>marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number or response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned <code>marker</code> value.</p>
    pub max_records: ::std::option::Option<i32>,
}
impl DescribeSnapshotSchedulesInput {
    /// <p>The unique identifier for the cluster whose snapshot schedules you want to view.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>A unique identifier for a snapshot schedule.</p>
    pub fn schedule_identifier(&self) -> ::std::option::Option<&str> {
        self.schedule_identifier.as_deref()
    }
    /// <p>The key value for a snapshot schedule tag.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_keys.is_none()`.
    pub fn tag_keys(&self) -> &[::std::string::String] {
        self.tag_keys.as_deref().unwrap_or_default()
    }
    /// <p>The value corresponding to the key of the snapshot schedule tag.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_values.is_none()`.
    pub fn tag_values(&self) -> &[::std::string::String] {
        self.tag_values.as_deref().unwrap_or_default()
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>marker</code> parameter and retrying the command. If the <code>marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number or response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned <code>marker</code> value.</p>
    pub fn max_records(&self) -> ::std::option::Option<i32> {
        self.max_records
    }
}
impl DescribeSnapshotSchedulesInput {
    /// Creates a new builder-style object to manufacture [`DescribeSnapshotSchedulesInput`](crate::operation::describe_snapshot_schedules::DescribeSnapshotSchedulesInput).
    pub fn builder() -> crate::operation::describe_snapshot_schedules::builders::DescribeSnapshotSchedulesInputBuilder {
        crate::operation::describe_snapshot_schedules::builders::DescribeSnapshotSchedulesInputBuilder::default()
    }
}

/// A builder for [`DescribeSnapshotSchedulesInput`](crate::operation::describe_snapshot_schedules::DescribeSnapshotSchedulesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSnapshotSchedulesInputBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tag_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_records: ::std::option::Option<i32>,
}
impl DescribeSnapshotSchedulesInputBuilder {
    /// <p>The unique identifier for the cluster whose snapshot schedules you want to view.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the cluster whose snapshot schedules you want to view.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The unique identifier for the cluster whose snapshot schedules you want to view.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>A unique identifier for a snapshot schedule.</p>
    pub fn schedule_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for a snapshot schedule.</p>
    pub fn set_schedule_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_identifier = input;
        self
    }
    /// <p>A unique identifier for a snapshot schedule.</p>
    pub fn get_schedule_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_identifier
    }
    /// Appends an item to `tag_keys`.
    ///
    /// To override the contents of this collection use [`set_tag_keys`](Self::set_tag_keys).
    ///
    /// <p>The key value for a snapshot schedule tag.</p>
    pub fn tag_keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_keys.unwrap_or_default();
        v.push(input.into());
        self.tag_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>The key value for a snapshot schedule tag.</p>
    pub fn set_tag_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_keys = input;
        self
    }
    /// <p>The key value for a snapshot schedule tag.</p>
    pub fn get_tag_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_keys
    }
    /// Appends an item to `tag_values`.
    ///
    /// To override the contents of this collection use [`set_tag_values`](Self::set_tag_values).
    ///
    /// <p>The value corresponding to the key of the snapshot schedule tag.</p>
    pub fn tag_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_values.unwrap_or_default();
        v.push(input.into());
        self.tag_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value corresponding to the key of the snapshot schedule tag.</p>
    pub fn set_tag_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_values = input;
        self
    }
    /// <p>The value corresponding to the key of the snapshot schedule tag.</p>
    pub fn get_tag_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_values
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>marker</code> parameter and retrying the command. If the <code>marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>marker</code> parameter and retrying the command. If the <code>marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>A value that indicates the starting point for the next set of response records in a subsequent request. If a value is returned in a response, you can retrieve the next set of records by providing this returned marker value in the <code>marker</code> parameter and retrying the command. If the <code>marker</code> field is empty, all response records have been retrieved for the request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>The maximum number or response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned <code>marker</code> value.</p>
    pub fn max_records(mut self, input: i32) -> Self {
        self.max_records = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number or response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned <code>marker</code> value.</p>
    pub fn set_max_records(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_records = input;
        self
    }
    /// <p>The maximum number or response records to return in each call. If the number of remaining response records exceeds the specified <code>MaxRecords</code> value, a value is returned in a <code>marker</code> field of the response. You can retrieve the next set of records by retrying the command with the returned <code>marker</code> value.</p>
    pub fn get_max_records(&self) -> &::std::option::Option<i32> {
        &self.max_records
    }
    /// Consumes the builder and constructs a [`DescribeSnapshotSchedulesInput`](crate::operation::describe_snapshot_schedules::DescribeSnapshotSchedulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_snapshot_schedules::DescribeSnapshotSchedulesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_snapshot_schedules::DescribeSnapshotSchedulesInput {
            cluster_identifier: self.cluster_identifier,
            schedule_identifier: self.schedule_identifier,
            tag_keys: self.tag_keys,
            tag_values: self.tag_values,
            marker: self.marker,
            max_records: self.max_records,
        })
    }
}
