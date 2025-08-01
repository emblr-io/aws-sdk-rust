// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A snapshot object that contains databases.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Snapshot {
    /// <p>The name of the namepsace.</p>
    pub namespace_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the namespace the snapshot was created from.</p>
    pub namespace_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the snapshot.</p>
    pub snapshot_name: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the snapshot was created.</p>
    pub snapshot_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The username of the database within a snapshot.</p>
    pub admin_username: ::std::option::Option<::std::string::String>,
    /// <p>The status of the snapshot.</p>
    pub status: ::std::option::Option<crate::types::SnapshotStatus>,
    /// <p>The unique identifier of the KMS key used to encrypt the snapshot.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The owner Amazon Web Services; account of the snapshot.</p>
    pub owner_account: ::std::option::Option<::std::string::String>,
    /// <p>The total size, in megabytes, of how big the snapshot is.</p>
    pub total_backup_size_in_mega_bytes: ::std::option::Option<f64>,
    /// <p>The size of the incremental backup in megabytes.</p>
    pub actual_incremental_backup_size_in_mega_bytes: ::std::option::Option<f64>,
    /// <p>The size in megabytes of the data that has been backed up to a snapshot.</p>
    pub backup_progress_in_mega_bytes: ::std::option::Option<f64>,
    /// <p>The rate at which data is backed up into a snapshot in megabytes per second.</p>
    pub current_backup_rate_in_mega_bytes_per_second: ::std::option::Option<f64>,
    /// <p>The estimated amount of seconds until the snapshot completes backup.</p>
    pub estimated_seconds_to_completion: ::std::option::Option<i64>,
    /// <p>The amount of time it took to back up data into a snapshot.</p>
    pub elapsed_time_in_seconds: ::std::option::Option<i64>,
    /// <p>The period of time, in days, of how long the snapshot is retained.</p>
    pub snapshot_retention_period: ::std::option::Option<i32>,
    /// <p>The amount of days until the snapshot is deleted.</p>
    pub snapshot_remaining_days: ::std::option::Option<i32>,
    /// <p>The timestamp of when data within the snapshot started getting retained.</p>
    pub snapshot_retention_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of the snapshot.</p>
    pub snapshot_arn: ::std::option::Option<::std::string::String>,
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a namespace.</p>
    pub accounts_with_restore_access: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a provisioned cluster.</p>
    pub accounts_with_provisioned_restore_access: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub admin_password_secret_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub admin_password_secret_kms_key_id: ::std::option::Option<::std::string::String>,
}
impl Snapshot {
    /// <p>The name of the namepsace.</p>
    pub fn namespace_name(&self) -> ::std::option::Option<&str> {
        self.namespace_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the namespace the snapshot was created from.</p>
    pub fn namespace_arn(&self) -> ::std::option::Option<&str> {
        self.namespace_arn.as_deref()
    }
    /// <p>The name of the snapshot.</p>
    pub fn snapshot_name(&self) -> ::std::option::Option<&str> {
        self.snapshot_name.as_deref()
    }
    /// <p>The timestamp of when the snapshot was created.</p>
    pub fn snapshot_create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.snapshot_create_time.as_ref()
    }
    /// <p>The username of the database within a snapshot.</p>
    pub fn admin_username(&self) -> ::std::option::Option<&str> {
        self.admin_username.as_deref()
    }
    /// <p>The status of the snapshot.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SnapshotStatus> {
        self.status.as_ref()
    }
    /// <p>The unique identifier of the KMS key used to encrypt the snapshot.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The owner Amazon Web Services; account of the snapshot.</p>
    pub fn owner_account(&self) -> ::std::option::Option<&str> {
        self.owner_account.as_deref()
    }
    /// <p>The total size, in megabytes, of how big the snapshot is.</p>
    pub fn total_backup_size_in_mega_bytes(&self) -> ::std::option::Option<f64> {
        self.total_backup_size_in_mega_bytes
    }
    /// <p>The size of the incremental backup in megabytes.</p>
    pub fn actual_incremental_backup_size_in_mega_bytes(&self) -> ::std::option::Option<f64> {
        self.actual_incremental_backup_size_in_mega_bytes
    }
    /// <p>The size in megabytes of the data that has been backed up to a snapshot.</p>
    pub fn backup_progress_in_mega_bytes(&self) -> ::std::option::Option<f64> {
        self.backup_progress_in_mega_bytes
    }
    /// <p>The rate at which data is backed up into a snapshot in megabytes per second.</p>
    pub fn current_backup_rate_in_mega_bytes_per_second(&self) -> ::std::option::Option<f64> {
        self.current_backup_rate_in_mega_bytes_per_second
    }
    /// <p>The estimated amount of seconds until the snapshot completes backup.</p>
    pub fn estimated_seconds_to_completion(&self) -> ::std::option::Option<i64> {
        self.estimated_seconds_to_completion
    }
    /// <p>The amount of time it took to back up data into a snapshot.</p>
    pub fn elapsed_time_in_seconds(&self) -> ::std::option::Option<i64> {
        self.elapsed_time_in_seconds
    }
    /// <p>The period of time, in days, of how long the snapshot is retained.</p>
    pub fn snapshot_retention_period(&self) -> ::std::option::Option<i32> {
        self.snapshot_retention_period
    }
    /// <p>The amount of days until the snapshot is deleted.</p>
    pub fn snapshot_remaining_days(&self) -> ::std::option::Option<i32> {
        self.snapshot_remaining_days
    }
    /// <p>The timestamp of when data within the snapshot started getting retained.</p>
    pub fn snapshot_retention_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.snapshot_retention_start_time.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot.</p>
    pub fn snapshot_arn(&self) -> ::std::option::Option<&str> {
        self.snapshot_arn.as_deref()
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a namespace.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.accounts_with_restore_access.is_none()`.
    pub fn accounts_with_restore_access(&self) -> &[::std::string::String] {
        self.accounts_with_restore_access.as_deref().unwrap_or_default()
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a provisioned cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.accounts_with_provisioned_restore_access.is_none()`.
    pub fn accounts_with_provisioned_restore_access(&self) -> &[::std::string::String] {
        self.accounts_with_provisioned_restore_access.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn admin_password_secret_arn(&self) -> ::std::option::Option<&str> {
        self.admin_password_secret_arn.as_deref()
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn admin_password_secret_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.admin_password_secret_kms_key_id.as_deref()
    }
}
impl Snapshot {
    /// Creates a new builder-style object to manufacture [`Snapshot`](crate::types::Snapshot).
    pub fn builder() -> crate::types::builders::SnapshotBuilder {
        crate::types::builders::SnapshotBuilder::default()
    }
}

/// A builder for [`Snapshot`](crate::types::Snapshot).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnapshotBuilder {
    pub(crate) namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) namespace_arn: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_name: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) admin_username: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SnapshotStatus>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) total_backup_size_in_mega_bytes: ::std::option::Option<f64>,
    pub(crate) actual_incremental_backup_size_in_mega_bytes: ::std::option::Option<f64>,
    pub(crate) backup_progress_in_mega_bytes: ::std::option::Option<f64>,
    pub(crate) current_backup_rate_in_mega_bytes_per_second: ::std::option::Option<f64>,
    pub(crate) estimated_seconds_to_completion: ::std::option::Option<i64>,
    pub(crate) elapsed_time_in_seconds: ::std::option::Option<i64>,
    pub(crate) snapshot_retention_period: ::std::option::Option<i32>,
    pub(crate) snapshot_remaining_days: ::std::option::Option<i32>,
    pub(crate) snapshot_retention_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) snapshot_arn: ::std::option::Option<::std::string::String>,
    pub(crate) accounts_with_restore_access: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) accounts_with_provisioned_restore_access: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) admin_password_secret_arn: ::std::option::Option<::std::string::String>,
    pub(crate) admin_password_secret_kms_key_id: ::std::option::Option<::std::string::String>,
}
impl SnapshotBuilder {
    /// <p>The name of the namepsace.</p>
    pub fn namespace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the namepsace.</p>
    pub fn set_namespace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_name = input;
        self
    }
    /// <p>The name of the namepsace.</p>
    pub fn get_namespace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_name
    }
    /// <p>The Amazon Resource Name (ARN) of the namespace the snapshot was created from.</p>
    pub fn namespace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the namespace the snapshot was created from.</p>
    pub fn set_namespace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the namespace the snapshot was created from.</p>
    pub fn get_namespace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_arn
    }
    /// <p>The name of the snapshot.</p>
    pub fn snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the snapshot.</p>
    pub fn set_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_name = input;
        self
    }
    /// <p>The name of the snapshot.</p>
    pub fn get_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_name
    }
    /// <p>The timestamp of when the snapshot was created.</p>
    pub fn snapshot_create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.snapshot_create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the snapshot was created.</p>
    pub fn set_snapshot_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.snapshot_create_time = input;
        self
    }
    /// <p>The timestamp of when the snapshot was created.</p>
    pub fn get_snapshot_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.snapshot_create_time
    }
    /// <p>The username of the database within a snapshot.</p>
    pub fn admin_username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The username of the database within a snapshot.</p>
    pub fn set_admin_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_username = input;
        self
    }
    /// <p>The username of the database within a snapshot.</p>
    pub fn get_admin_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_username
    }
    /// <p>The status of the snapshot.</p>
    pub fn status(mut self, input: crate::types::SnapshotStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the snapshot.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SnapshotStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the snapshot.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SnapshotStatus> {
        &self.status
    }
    /// <p>The unique identifier of the KMS key used to encrypt the snapshot.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the KMS key used to encrypt the snapshot.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The unique identifier of the KMS key used to encrypt the snapshot.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The owner Amazon Web Services; account of the snapshot.</p>
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner Amazon Web Services; account of the snapshot.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The owner Amazon Web Services; account of the snapshot.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// <p>The total size, in megabytes, of how big the snapshot is.</p>
    pub fn total_backup_size_in_mega_bytes(mut self, input: f64) -> Self {
        self.total_backup_size_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total size, in megabytes, of how big the snapshot is.</p>
    pub fn set_total_backup_size_in_mega_bytes(mut self, input: ::std::option::Option<f64>) -> Self {
        self.total_backup_size_in_mega_bytes = input;
        self
    }
    /// <p>The total size, in megabytes, of how big the snapshot is.</p>
    pub fn get_total_backup_size_in_mega_bytes(&self) -> &::std::option::Option<f64> {
        &self.total_backup_size_in_mega_bytes
    }
    /// <p>The size of the incremental backup in megabytes.</p>
    pub fn actual_incremental_backup_size_in_mega_bytes(mut self, input: f64) -> Self {
        self.actual_incremental_backup_size_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the incremental backup in megabytes.</p>
    pub fn set_actual_incremental_backup_size_in_mega_bytes(mut self, input: ::std::option::Option<f64>) -> Self {
        self.actual_incremental_backup_size_in_mega_bytes = input;
        self
    }
    /// <p>The size of the incremental backup in megabytes.</p>
    pub fn get_actual_incremental_backup_size_in_mega_bytes(&self) -> &::std::option::Option<f64> {
        &self.actual_incremental_backup_size_in_mega_bytes
    }
    /// <p>The size in megabytes of the data that has been backed up to a snapshot.</p>
    pub fn backup_progress_in_mega_bytes(mut self, input: f64) -> Self {
        self.backup_progress_in_mega_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size in megabytes of the data that has been backed up to a snapshot.</p>
    pub fn set_backup_progress_in_mega_bytes(mut self, input: ::std::option::Option<f64>) -> Self {
        self.backup_progress_in_mega_bytes = input;
        self
    }
    /// <p>The size in megabytes of the data that has been backed up to a snapshot.</p>
    pub fn get_backup_progress_in_mega_bytes(&self) -> &::std::option::Option<f64> {
        &self.backup_progress_in_mega_bytes
    }
    /// <p>The rate at which data is backed up into a snapshot in megabytes per second.</p>
    pub fn current_backup_rate_in_mega_bytes_per_second(mut self, input: f64) -> Self {
        self.current_backup_rate_in_mega_bytes_per_second = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rate at which data is backed up into a snapshot in megabytes per second.</p>
    pub fn set_current_backup_rate_in_mega_bytes_per_second(mut self, input: ::std::option::Option<f64>) -> Self {
        self.current_backup_rate_in_mega_bytes_per_second = input;
        self
    }
    /// <p>The rate at which data is backed up into a snapshot in megabytes per second.</p>
    pub fn get_current_backup_rate_in_mega_bytes_per_second(&self) -> &::std::option::Option<f64> {
        &self.current_backup_rate_in_mega_bytes_per_second
    }
    /// <p>The estimated amount of seconds until the snapshot completes backup.</p>
    pub fn estimated_seconds_to_completion(mut self, input: i64) -> Self {
        self.estimated_seconds_to_completion = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated amount of seconds until the snapshot completes backup.</p>
    pub fn set_estimated_seconds_to_completion(mut self, input: ::std::option::Option<i64>) -> Self {
        self.estimated_seconds_to_completion = input;
        self
    }
    /// <p>The estimated amount of seconds until the snapshot completes backup.</p>
    pub fn get_estimated_seconds_to_completion(&self) -> &::std::option::Option<i64> {
        &self.estimated_seconds_to_completion
    }
    /// <p>The amount of time it took to back up data into a snapshot.</p>
    pub fn elapsed_time_in_seconds(mut self, input: i64) -> Self {
        self.elapsed_time_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time it took to back up data into a snapshot.</p>
    pub fn set_elapsed_time_in_seconds(mut self, input: ::std::option::Option<i64>) -> Self {
        self.elapsed_time_in_seconds = input;
        self
    }
    /// <p>The amount of time it took to back up data into a snapshot.</p>
    pub fn get_elapsed_time_in_seconds(&self) -> &::std::option::Option<i64> {
        &self.elapsed_time_in_seconds
    }
    /// <p>The period of time, in days, of how long the snapshot is retained.</p>
    pub fn snapshot_retention_period(mut self, input: i32) -> Self {
        self.snapshot_retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The period of time, in days, of how long the snapshot is retained.</p>
    pub fn set_snapshot_retention_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.snapshot_retention_period = input;
        self
    }
    /// <p>The period of time, in days, of how long the snapshot is retained.</p>
    pub fn get_snapshot_retention_period(&self) -> &::std::option::Option<i32> {
        &self.snapshot_retention_period
    }
    /// <p>The amount of days until the snapshot is deleted.</p>
    pub fn snapshot_remaining_days(mut self, input: i32) -> Self {
        self.snapshot_remaining_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of days until the snapshot is deleted.</p>
    pub fn set_snapshot_remaining_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.snapshot_remaining_days = input;
        self
    }
    /// <p>The amount of days until the snapshot is deleted.</p>
    pub fn get_snapshot_remaining_days(&self) -> &::std::option::Option<i32> {
        &self.snapshot_remaining_days
    }
    /// <p>The timestamp of when data within the snapshot started getting retained.</p>
    pub fn snapshot_retention_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.snapshot_retention_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when data within the snapshot started getting retained.</p>
    pub fn set_snapshot_retention_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.snapshot_retention_start_time = input;
        self
    }
    /// <p>The timestamp of when data within the snapshot started getting retained.</p>
    pub fn get_snapshot_retention_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.snapshot_retention_start_time
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot.</p>
    pub fn snapshot_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot.</p>
    pub fn set_snapshot_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the snapshot.</p>
    pub fn get_snapshot_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_arn
    }
    /// Appends an item to `accounts_with_restore_access`.
    ///
    /// To override the contents of this collection use [`set_accounts_with_restore_access`](Self::set_accounts_with_restore_access).
    ///
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a namespace.</p>
    pub fn accounts_with_restore_access(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.accounts_with_restore_access.unwrap_or_default();
        v.push(input.into());
        self.accounts_with_restore_access = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a namespace.</p>
    pub fn set_accounts_with_restore_access(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.accounts_with_restore_access = input;
        self
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a namespace.</p>
    pub fn get_accounts_with_restore_access(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.accounts_with_restore_access
    }
    /// Appends an item to `accounts_with_provisioned_restore_access`.
    ///
    /// To override the contents of this collection use [`set_accounts_with_provisioned_restore_access`](Self::set_accounts_with_provisioned_restore_access).
    ///
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a provisioned cluster.</p>
    pub fn accounts_with_provisioned_restore_access(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.accounts_with_provisioned_restore_access.unwrap_or_default();
        v.push(input.into());
        self.accounts_with_provisioned_restore_access = ::std::option::Option::Some(v);
        self
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a provisioned cluster.</p>
    pub fn set_accounts_with_provisioned_restore_access(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.accounts_with_provisioned_restore_access = input;
        self
    }
    /// <p>All of the Amazon Web Services accounts that have access to restore a snapshot to a provisioned cluster.</p>
    pub fn get_accounts_with_provisioned_restore_access(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.accounts_with_provisioned_restore_access
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn admin_password_secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_password_secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn set_admin_password_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_password_secret_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn get_admin_password_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_password_secret_arn
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn admin_password_secret_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_password_secret_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn set_admin_password_secret_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_password_secret_kms_key_id = input;
        self
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn get_admin_password_secret_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_password_secret_kms_key_id
    }
    /// Consumes the builder and constructs a [`Snapshot`](crate::types::Snapshot).
    pub fn build(self) -> crate::types::Snapshot {
        crate::types::Snapshot {
            namespace_name: self.namespace_name,
            namespace_arn: self.namespace_arn,
            snapshot_name: self.snapshot_name,
            snapshot_create_time: self.snapshot_create_time,
            admin_username: self.admin_username,
            status: self.status,
            kms_key_id: self.kms_key_id,
            owner_account: self.owner_account,
            total_backup_size_in_mega_bytes: self.total_backup_size_in_mega_bytes,
            actual_incremental_backup_size_in_mega_bytes: self.actual_incremental_backup_size_in_mega_bytes,
            backup_progress_in_mega_bytes: self.backup_progress_in_mega_bytes,
            current_backup_rate_in_mega_bytes_per_second: self.current_backup_rate_in_mega_bytes_per_second,
            estimated_seconds_to_completion: self.estimated_seconds_to_completion,
            elapsed_time_in_seconds: self.elapsed_time_in_seconds,
            snapshot_retention_period: self.snapshot_retention_period,
            snapshot_remaining_days: self.snapshot_remaining_days,
            snapshot_retention_start_time: self.snapshot_retention_start_time,
            snapshot_arn: self.snapshot_arn,
            accounts_with_restore_access: self.accounts_with_restore_access,
            accounts_with_provisioned_restore_access: self.accounts_with_provisioned_restore_access,
            admin_password_secret_arn: self.admin_password_secret_arn,
            admin_password_secret_kms_key_id: self.admin_password_secret_kms_key_id,
        }
    }
}
