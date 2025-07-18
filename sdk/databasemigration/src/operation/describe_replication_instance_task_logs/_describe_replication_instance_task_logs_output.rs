// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReplicationInstanceTaskLogsOutput {
    /// <p>The Amazon Resource Name (ARN) of the replication instance.</p>
    pub replication_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>An array of replication task log metadata. Each member of the array contains the replication task name, ARN, and task log size (in bytes).</p>
    pub replication_instance_task_logs: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationInstanceTaskLog>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeReplicationInstanceTaskLogsOutput {
    /// <p>The Amazon Resource Name (ARN) of the replication instance.</p>
    pub fn replication_instance_arn(&self) -> ::std::option::Option<&str> {
        self.replication_instance_arn.as_deref()
    }
    /// <p>An array of replication task log metadata. Each member of the array contains the replication task name, ARN, and task log size (in bytes).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_instance_task_logs.is_none()`.
    pub fn replication_instance_task_logs(&self) -> &[crate::types::ReplicationInstanceTaskLog] {
        self.replication_instance_task_logs.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeReplicationInstanceTaskLogsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeReplicationInstanceTaskLogsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeReplicationInstanceTaskLogsOutput`](crate::operation::describe_replication_instance_task_logs::DescribeReplicationInstanceTaskLogsOutput).
    pub fn builder() -> crate::operation::describe_replication_instance_task_logs::builders::DescribeReplicationInstanceTaskLogsOutputBuilder {
        crate::operation::describe_replication_instance_task_logs::builders::DescribeReplicationInstanceTaskLogsOutputBuilder::default()
    }
}

/// A builder for [`DescribeReplicationInstanceTaskLogsOutput`](crate::operation::describe_replication_instance_task_logs::DescribeReplicationInstanceTaskLogsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReplicationInstanceTaskLogsOutputBuilder {
    pub(crate) replication_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) replication_instance_task_logs: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationInstanceTaskLog>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeReplicationInstanceTaskLogsOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication instance.</p>
    pub fn replication_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication instance.</p>
    pub fn set_replication_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication instance.</p>
    pub fn get_replication_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_instance_arn
    }
    /// Appends an item to `replication_instance_task_logs`.
    ///
    /// To override the contents of this collection use [`set_replication_instance_task_logs`](Self::set_replication_instance_task_logs).
    ///
    /// <p>An array of replication task log metadata. Each member of the array contains the replication task name, ARN, and task log size (in bytes).</p>
    pub fn replication_instance_task_logs(mut self, input: crate::types::ReplicationInstanceTaskLog) -> Self {
        let mut v = self.replication_instance_task_logs.unwrap_or_default();
        v.push(input);
        self.replication_instance_task_logs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of replication task log metadata. Each member of the array contains the replication task name, ARN, and task log size (in bytes).</p>
    pub fn set_replication_instance_task_logs(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationInstanceTaskLog>>,
    ) -> Self {
        self.replication_instance_task_logs = input;
        self
    }
    /// <p>An array of replication task log metadata. Each member of the array contains the replication task name, ARN, and task log size (in bytes).</p>
    pub fn get_replication_instance_task_logs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicationInstanceTaskLog>> {
        &self.replication_instance_task_logs
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeReplicationInstanceTaskLogsOutput`](crate::operation::describe_replication_instance_task_logs::DescribeReplicationInstanceTaskLogsOutput).
    pub fn build(self) -> crate::operation::describe_replication_instance_task_logs::DescribeReplicationInstanceTaskLogsOutput {
        crate::operation::describe_replication_instance_task_logs::DescribeReplicationInstanceTaskLogsOutput {
            replication_instance_arn: self.replication_instance_arn,
            replication_instance_task_logs: self.replication_instance_task_logs,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
