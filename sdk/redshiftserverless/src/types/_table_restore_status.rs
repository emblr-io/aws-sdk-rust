// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a table restore request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableRestoreStatus {
    /// <p>The ID of the RestoreTableFromSnapshot request.</p>
    pub table_restore_request_id: ::std::option::Option<::std::string::String>,
    /// <p>A value that describes the current state of the table restore request. Possible values are <code>SUCCEEDED</code>, <code>FAILED</code>, <code>CANCELED</code>, <code>PENDING</code>, and <code>IN_PROGRESS</code>.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>A message that explains the returned status. For example, if the status of the operation is <code>FAILED</code>, the message explains why the operation failed.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The time that the table restore request was made, in Universal Coordinated Time (UTC).</p>
    pub request_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The namespace of the table being restored from.</p>
    pub namespace_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the workgroup being restored from.</p>
    pub workgroup_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the snapshot being restored from.</p>
    pub snapshot_name: ::std::option::Option<::std::string::String>,
    /// <p>The amount of data restored to the new table so far, in megabytes (MB).</p>
    pub progress_in_mega_bytes: ::std::option::Option<i64>,
    /// <p>The total amount of data to restore to the new table, in megabytes (MB).</p>
    pub total_data_in_mega_bytes: ::std::option::Option<i64>,
    /// <p>The name of the source database being restored from.</p>
    pub source_database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the source schema being restored from.</p>
    pub source_schema_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the source table being restored from.</p>
    pub source_table_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the database to restore to.</p>
    pub target_database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the schema to restore to.</p>
    pub target_schema_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table to create from the restore operation.</p>
    pub new_table_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the recovery point being restored from.</p>
    pub recovery_point_id: ::std::option::Option<::std::string::String>,
}
impl TableRestoreStatus {
    /// <p>The ID of the RestoreTableFromSnapshot request.</p>
    pub fn table_restore_request_id(&self) -> ::std::option::Option<&str> {
        self.table_restore_request_id.as_deref()
    }
    /// <p>A value that describes the current state of the table restore request. Possible values are <code>SUCCEEDED</code>, <code>FAILED</code>, <code>CANCELED</code>, <code>PENDING</code>, and <code>IN_PROGRESS</code>.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>A message that explains the returned status. For example, if the status of the operation is <code>FAILED</code>, the message explains why the operation failed.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>The time that the table restore request was made, in Universal Coordinated Time (UTC).</p>
    pub fn request_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.request_time.as_ref()
    }
    /// <p>The namespace of the table being restored from.</p>
    pub fn namespace_name(&self) -> ::std::option::Option<&str> {
        self.namespace_name.as_deref()
    }
    /// <p>The name of the workgroup being restored from.</p>
    pub fn workgroup_name(&self) -> ::std::option::Option<&str> {
        self.workgroup_name.as_deref()
    }
    /// <p>The name of the snapshot being restored from.</p>
    pub fn snapshot_name(&self) -> ::std::option::Option<&str> {
        self.snapshot_name.as_deref()
    }
    /// <p>The amount of data restored to the new table so far, in megabytes (MB).</p>
    pub fn progress_in_mega_bytes(&self) -> ::std::option::Option<i64> {
        self.progress_in_mega_bytes
    }
    /// <p>The total amount of data to restore to the new table, in megabytes (MB).</p>
    pub fn total_data_in_mega_bytes(&self) -> ::std::option::Option<i64> {
        self.total_data_in_mega_bytes
    }
    /// <p>The name of the source database being restored from.</p>
    pub fn source_database_name(&self) -> ::std::option::Option<&str> {
        self.source_database_name.as_deref()
    }
    /// <p>The name of the source schema being restored from.</p>
    pub fn source_schema_name(&self) -> ::std::option::Option<&str> {
        self.source_schema_name.as_deref()
    }
    /// <p>The name of the source table being restored from.</p>
    pub fn source_table_name(&self) -> ::std::option::Option<&str> {
        self.source_table_name.as_deref()
    }
    /// <p>The name of the database to restore to.</p>
    pub fn target_database_name(&self) -> ::std::option::Option<&str> {
        self.target_database_name.as_deref()
    }
    /// <p>The name of the schema to restore to.</p>
    pub fn target_schema_name(&self) -> ::std::option::Option<&str> {
        self.target_schema_name.as_deref()
    }
    /// <p>The name of the table to create from the restore operation.</p>
    pub fn new_table_name(&self) -> ::std::option::Option<&str> {
        self.new_table_name.as_deref()
    }
    /// <p>The ID of the recovery point being restored from.</p>
    pub fn recovery_point_id(&self) -> ::std::option::Option<&str> {
        self.recovery_point_id.as_deref()
    }
}
impl TableRestoreStatus {
    /// Creates a new builder-style object to manufacture [`TableRestoreStatus`](crate::types::TableRestoreStatus).
    pub fn builder() -> crate::types::builders::TableRestoreStatusBuilder {
        crate::types::builders::TableRestoreStatusBuilder::default()
    }
}

/// A builder for [`TableRestoreStatus`](crate::types::TableRestoreStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableRestoreStatusBuilder {
    pub(crate) table_restore_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) request_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) workgroup_name: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_name: ::std::option::Option<::std::string::String>,
    pub(crate) progress_in_mega_bytes: ::std::option::Option<i64>,
    pub(crate) total_data_in_mega_bytes: ::std::option::Option<i64>,
    pub(crate) source_database_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_schema_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_table_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_database_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_schema_name: ::std::option::Option<::std::string::String>,
    pub(crate) new_table_name: ::std::option::Option<::std::string::String>,
    pub(crate) recovery_point_id: ::std::option::Option<::std::string::String>,
}
impl TableRestoreStatusBuilder {
    /// <p>The ID of the RestoreTableFromSnapshot request.</p>
    pub fn table_restore_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_restore_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the RestoreTableFromSnapshot request.</p>
    pub fn set_table_restore_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_restore_request_id = input;
        self
    }
    /// <p>The ID of the RestoreTableFromSnapshot request.</p>
    pub fn get_table_restore_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_restore_request_id
    }
    /// <p>A value that describes the current state of the table restore request. Possible values are <code>SUCCEEDED</code>, <code>FAILED</code>, <code>CANCELED</code>, <code>PENDING</code>, and <code>IN_PROGRESS</code>.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that describes the current state of the table restore request. Possible values are <code>SUCCEEDED</code>, <code>FAILED</code>, <code>CANCELED</code>, <code>PENDING</code>, and <code>IN_PROGRESS</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>A value that describes the current state of the table restore request. Possible values are <code>SUCCEEDED</code>, <code>FAILED</code>, <code>CANCELED</code>, <code>PENDING</code>, and <code>IN_PROGRESS</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>A message that explains the returned status. For example, if the status of the operation is <code>FAILED</code>, the message explains why the operation failed.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that explains the returned status. For example, if the status of the operation is <code>FAILED</code>, the message explains why the operation failed.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message that explains the returned status. For example, if the status of the operation is <code>FAILED</code>, the message explains why the operation failed.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>The time that the table restore request was made, in Universal Coordinated Time (UTC).</p>
    pub fn request_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.request_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the table restore request was made, in Universal Coordinated Time (UTC).</p>
    pub fn set_request_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.request_time = input;
        self
    }
    /// <p>The time that the table restore request was made, in Universal Coordinated Time (UTC).</p>
    pub fn get_request_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.request_time
    }
    /// <p>The namespace of the table being restored from.</p>
    pub fn namespace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the table being restored from.</p>
    pub fn set_namespace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_name = input;
        self
    }
    /// <p>The namespace of the table being restored from.</p>
    pub fn get_namespace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_name
    }
    /// <p>The name of the workgroup being restored from.</p>
    pub fn workgroup_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workgroup_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workgroup being restored from.</p>
    pub fn set_workgroup_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workgroup_name = input;
        self
    }
    /// <p>The name of the workgroup being restored from.</p>
    pub fn get_workgroup_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.workgroup_name
    }
    /// <p>The name of the snapshot being restored from.</p>
    pub fn snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the snapshot being restored from.</p>
    pub fn set_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_name = input;
        self
    }
    /// <p>The name of the snapshot being restored from.</p>
    pub fn get_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_name
    }
    /// <p>The amount of data restored to the new table so far, in megabytes (MB).</p>
    pub fn progress_in_mega_bytes(mut self, input: i64) -> Self {
        self.progress_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of data restored to the new table so far, in megabytes (MB).</p>
    pub fn set_progress_in_mega_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.progress_in_mega_bytes = input;
        self
    }
    /// <p>The amount of data restored to the new table so far, in megabytes (MB).</p>
    pub fn get_progress_in_mega_bytes(&self) -> &::std::option::Option<i64> {
        &self.progress_in_mega_bytes
    }
    /// <p>The total amount of data to restore to the new table, in megabytes (MB).</p>
    pub fn total_data_in_mega_bytes(mut self, input: i64) -> Self {
        self.total_data_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total amount of data to restore to the new table, in megabytes (MB).</p>
    pub fn set_total_data_in_mega_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_data_in_mega_bytes = input;
        self
    }
    /// <p>The total amount of data to restore to the new table, in megabytes (MB).</p>
    pub fn get_total_data_in_mega_bytes(&self) -> &::std::option::Option<i64> {
        &self.total_data_in_mega_bytes
    }
    /// <p>The name of the source database being restored from.</p>
    pub fn source_database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source database being restored from.</p>
    pub fn set_source_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_database_name = input;
        self
    }
    /// <p>The name of the source database being restored from.</p>
    pub fn get_source_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_database_name
    }
    /// <p>The name of the source schema being restored from.</p>
    pub fn source_schema_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_schema_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source schema being restored from.</p>
    pub fn set_source_schema_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_schema_name = input;
        self
    }
    /// <p>The name of the source schema being restored from.</p>
    pub fn get_source_schema_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_schema_name
    }
    /// <p>The name of the source table being restored from.</p>
    pub fn source_table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source table being restored from.</p>
    pub fn set_source_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_table_name = input;
        self
    }
    /// <p>The name of the source table being restored from.</p>
    pub fn get_source_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_table_name
    }
    /// <p>The name of the database to restore to.</p>
    pub fn target_database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database to restore to.</p>
    pub fn set_target_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_database_name = input;
        self
    }
    /// <p>The name of the database to restore to.</p>
    pub fn get_target_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_database_name
    }
    /// <p>The name of the schema to restore to.</p>
    pub fn target_schema_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_schema_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schema to restore to.</p>
    pub fn set_target_schema_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_schema_name = input;
        self
    }
    /// <p>The name of the schema to restore to.</p>
    pub fn get_target_schema_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_schema_name
    }
    /// <p>The name of the table to create from the restore operation.</p>
    pub fn new_table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table to create from the restore operation.</p>
    pub fn set_new_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_table_name = input;
        self
    }
    /// <p>The name of the table to create from the restore operation.</p>
    pub fn get_new_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_table_name
    }
    /// <p>The ID of the recovery point being restored from.</p>
    pub fn recovery_point_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recovery_point_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the recovery point being restored from.</p>
    pub fn set_recovery_point_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recovery_point_id = input;
        self
    }
    /// <p>The ID of the recovery point being restored from.</p>
    pub fn get_recovery_point_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recovery_point_id
    }
    /// Consumes the builder and constructs a [`TableRestoreStatus`](crate::types::TableRestoreStatus).
    pub fn build(self) -> crate::types::TableRestoreStatus {
        crate::types::TableRestoreStatus {
            table_restore_request_id: self.table_restore_request_id,
            status: self.status,
            message: self.message,
            request_time: self.request_time,
            namespace_name: self.namespace_name,
            workgroup_name: self.workgroup_name,
            snapshot_name: self.snapshot_name,
            progress_in_mega_bytes: self.progress_in_mega_bytes,
            total_data_in_mega_bytes: self.total_data_in_mega_bytes,
            source_database_name: self.source_database_name,
            source_schema_name: self.source_schema_name,
            source_table_name: self.source_table_name,
            target_database_name: self.target_database_name,
            target_schema_name: self.target_schema_name,
            new_table_name: self.new_table_name,
            recovery_point_id: self.recovery_point_id,
        }
    }
}
