// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about the Amazon SNS event notifications for the specified backup vault.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsBackupBackupVaultNotificationsDetails {
    /// <p>An array of events that indicate the status of jobs to back up resources to the backup vault. The following events are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>BACKUP_JOB_STARTED | BACKUP_JOB_COMPLETED</code></p></li>
    /// <li>
    /// <p><code>COPY_JOB_STARTED | COPY_JOB_SUCCESSFUL | COPY_JOB_FAILED</code></p></li>
    /// <li>
    /// <p><code>RESTORE_JOB_STARTED | RESTORE_JOB_COMPLETED | RECOVERY_POINT_MODIFIED</code></p></li>
    /// <li>
    /// <p><code>S3_BACKUP_OBJECT_FAILED | S3_RESTORE_OBJECT_FAILED</code></p></li>
    /// </ul>
    pub backup_vault_events: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the Amazon SNS topic for a backup vault's events.</p>
    pub sns_topic_arn: ::std::option::Option<::std::string::String>,
}
impl AwsBackupBackupVaultNotificationsDetails {
    /// <p>An array of events that indicate the status of jobs to back up resources to the backup vault. The following events are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>BACKUP_JOB_STARTED | BACKUP_JOB_COMPLETED</code></p></li>
    /// <li>
    /// <p><code>COPY_JOB_STARTED | COPY_JOB_SUCCESSFUL | COPY_JOB_FAILED</code></p></li>
    /// <li>
    /// <p><code>RESTORE_JOB_STARTED | RESTORE_JOB_COMPLETED | RECOVERY_POINT_MODIFIED</code></p></li>
    /// <li>
    /// <p><code>S3_BACKUP_OBJECT_FAILED | S3_RESTORE_OBJECT_FAILED</code></p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.backup_vault_events.is_none()`.
    pub fn backup_vault_events(&self) -> &[::std::string::String] {
        self.backup_vault_events.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the Amazon SNS topic for a backup vault's events.</p>
    pub fn sns_topic_arn(&self) -> ::std::option::Option<&str> {
        self.sns_topic_arn.as_deref()
    }
}
impl AwsBackupBackupVaultNotificationsDetails {
    /// Creates a new builder-style object to manufacture [`AwsBackupBackupVaultNotificationsDetails`](crate::types::AwsBackupBackupVaultNotificationsDetails).
    pub fn builder() -> crate::types::builders::AwsBackupBackupVaultNotificationsDetailsBuilder {
        crate::types::builders::AwsBackupBackupVaultNotificationsDetailsBuilder::default()
    }
}

/// A builder for [`AwsBackupBackupVaultNotificationsDetails`](crate::types::AwsBackupBackupVaultNotificationsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsBackupBackupVaultNotificationsDetailsBuilder {
    pub(crate) backup_vault_events: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) sns_topic_arn: ::std::option::Option<::std::string::String>,
}
impl AwsBackupBackupVaultNotificationsDetailsBuilder {
    /// Appends an item to `backup_vault_events`.
    ///
    /// To override the contents of this collection use [`set_backup_vault_events`](Self::set_backup_vault_events).
    ///
    /// <p>An array of events that indicate the status of jobs to back up resources to the backup vault. The following events are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>BACKUP_JOB_STARTED | BACKUP_JOB_COMPLETED</code></p></li>
    /// <li>
    /// <p><code>COPY_JOB_STARTED | COPY_JOB_SUCCESSFUL | COPY_JOB_FAILED</code></p></li>
    /// <li>
    /// <p><code>RESTORE_JOB_STARTED | RESTORE_JOB_COMPLETED | RECOVERY_POINT_MODIFIED</code></p></li>
    /// <li>
    /// <p><code>S3_BACKUP_OBJECT_FAILED | S3_RESTORE_OBJECT_FAILED</code></p></li>
    /// </ul>
    pub fn backup_vault_events(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.backup_vault_events.unwrap_or_default();
        v.push(input.into());
        self.backup_vault_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of events that indicate the status of jobs to back up resources to the backup vault. The following events are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>BACKUP_JOB_STARTED | BACKUP_JOB_COMPLETED</code></p></li>
    /// <li>
    /// <p><code>COPY_JOB_STARTED | COPY_JOB_SUCCESSFUL | COPY_JOB_FAILED</code></p></li>
    /// <li>
    /// <p><code>RESTORE_JOB_STARTED | RESTORE_JOB_COMPLETED | RECOVERY_POINT_MODIFIED</code></p></li>
    /// <li>
    /// <p><code>S3_BACKUP_OBJECT_FAILED | S3_RESTORE_OBJECT_FAILED</code></p></li>
    /// </ul>
    pub fn set_backup_vault_events(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.backup_vault_events = input;
        self
    }
    /// <p>An array of events that indicate the status of jobs to back up resources to the backup vault. The following events are supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>BACKUP_JOB_STARTED | BACKUP_JOB_COMPLETED</code></p></li>
    /// <li>
    /// <p><code>COPY_JOB_STARTED | COPY_JOB_SUCCESSFUL | COPY_JOB_FAILED</code></p></li>
    /// <li>
    /// <p><code>RESTORE_JOB_STARTED | RESTORE_JOB_COMPLETED | RECOVERY_POINT_MODIFIED</code></p></li>
    /// <li>
    /// <p><code>S3_BACKUP_OBJECT_FAILED | S3_RESTORE_OBJECT_FAILED</code></p></li>
    /// </ul>
    pub fn get_backup_vault_events(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.backup_vault_events
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the Amazon SNS topic for a backup vault's events.</p>
    pub fn sns_topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the Amazon SNS topic for a backup vault's events.</p>
    pub fn set_sns_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_topic_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies the Amazon SNS topic for a backup vault's events.</p>
    pub fn get_sns_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_topic_arn
    }
    /// Consumes the builder and constructs a [`AwsBackupBackupVaultNotificationsDetails`](crate::types::AwsBackupBackupVaultNotificationsDetails).
    pub fn build(self) -> crate::types::AwsBackupBackupVaultNotificationsDetails {
        crate::types::AwsBackupBackupVaultNotificationsDetails {
            backup_vault_events: self.backup_vault_events,
            sns_topic_arn: self.sns_topic_arn,
        }
    }
}
