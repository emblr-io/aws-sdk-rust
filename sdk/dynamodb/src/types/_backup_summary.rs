// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details for the backup.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BackupSummary {
    /// <p>Name of the table.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier for the table.</p>
    pub table_id: ::std::option::Option<::std::string::String>,
    /// <p>ARN associated with the table.</p>
    pub table_arn: ::std::option::Option<::std::string::String>,
    /// <p>ARN associated with the backup.</p>
    pub backup_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of the specified backup.</p>
    pub backup_name: ::std::option::Option<::std::string::String>,
    /// <p>Time at which the backup was created.</p>
    pub backup_creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Time at which the automatic on-demand backup created by DynamoDB will expire. This <code>SYSTEM</code> on-demand backup expires automatically 35 days after its creation.</p>
    pub backup_expiry_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Backup can be in one of the following states: CREATING, ACTIVE, DELETED.</p>
    pub backup_status: ::std::option::Option<crate::types::BackupStatus>,
    /// <p>BackupType:</p>
    /// <ul>
    /// <li>
    /// <p><code>USER</code> - You create and manage these using the on-demand backup feature.</p></li>
    /// <li>
    /// <p><code>SYSTEM</code> - If you delete a table with point-in-time recovery enabled, a <code>SYSTEM</code> backup is automatically created and is retained for 35 days (at no additional cost). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.</p></li>
    /// <li>
    /// <p><code>AWS_BACKUP</code> - On-demand backup created by you from Backup service.</p></li>
    /// </ul>
    pub backup_type: ::std::option::Option<crate::types::BackupType>,
    /// <p>Size of the backup in bytes.</p>
    pub backup_size_bytes: ::std::option::Option<i64>,
}
impl BackupSummary {
    /// <p>Name of the table.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>Unique identifier for the table.</p>
    pub fn table_id(&self) -> ::std::option::Option<&str> {
        self.table_id.as_deref()
    }
    /// <p>ARN associated with the table.</p>
    pub fn table_arn(&self) -> ::std::option::Option<&str> {
        self.table_arn.as_deref()
    }
    /// <p>ARN associated with the backup.</p>
    pub fn backup_arn(&self) -> ::std::option::Option<&str> {
        self.backup_arn.as_deref()
    }
    /// <p>Name of the specified backup.</p>
    pub fn backup_name(&self) -> ::std::option::Option<&str> {
        self.backup_name.as_deref()
    }
    /// <p>Time at which the backup was created.</p>
    pub fn backup_creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.backup_creation_date_time.as_ref()
    }
    /// <p>Time at which the automatic on-demand backup created by DynamoDB will expire. This <code>SYSTEM</code> on-demand backup expires automatically 35 days after its creation.</p>
    pub fn backup_expiry_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.backup_expiry_date_time.as_ref()
    }
    /// <p>Backup can be in one of the following states: CREATING, ACTIVE, DELETED.</p>
    pub fn backup_status(&self) -> ::std::option::Option<&crate::types::BackupStatus> {
        self.backup_status.as_ref()
    }
    /// <p>BackupType:</p>
    /// <ul>
    /// <li>
    /// <p><code>USER</code> - You create and manage these using the on-demand backup feature.</p></li>
    /// <li>
    /// <p><code>SYSTEM</code> - If you delete a table with point-in-time recovery enabled, a <code>SYSTEM</code> backup is automatically created and is retained for 35 days (at no additional cost). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.</p></li>
    /// <li>
    /// <p><code>AWS_BACKUP</code> - On-demand backup created by you from Backup service.</p></li>
    /// </ul>
    pub fn backup_type(&self) -> ::std::option::Option<&crate::types::BackupType> {
        self.backup_type.as_ref()
    }
    /// <p>Size of the backup in bytes.</p>
    pub fn backup_size_bytes(&self) -> ::std::option::Option<i64> {
        self.backup_size_bytes
    }
}
impl BackupSummary {
    /// Creates a new builder-style object to manufacture [`BackupSummary`](crate::types::BackupSummary).
    pub fn builder() -> crate::types::builders::BackupSummaryBuilder {
        crate::types::builders::BackupSummaryBuilder::default()
    }
}

/// A builder for [`BackupSummary`](crate::types::BackupSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BackupSummaryBuilder {
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_id: ::std::option::Option<::std::string::String>,
    pub(crate) table_arn: ::std::option::Option<::std::string::String>,
    pub(crate) backup_arn: ::std::option::Option<::std::string::String>,
    pub(crate) backup_name: ::std::option::Option<::std::string::String>,
    pub(crate) backup_creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) backup_expiry_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) backup_status: ::std::option::Option<crate::types::BackupStatus>,
    pub(crate) backup_type: ::std::option::Option<crate::types::BackupType>,
    pub(crate) backup_size_bytes: ::std::option::Option<i64>,
}
impl BackupSummaryBuilder {
    /// <p>Name of the table.</p>
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the table.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>Name of the table.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>Unique identifier for the table.</p>
    pub fn table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier for the table.</p>
    pub fn set_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_id = input;
        self
    }
    /// <p>Unique identifier for the table.</p>
    pub fn get_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_id
    }
    /// <p>ARN associated with the table.</p>
    pub fn table_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN associated with the table.</p>
    pub fn set_table_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_arn = input;
        self
    }
    /// <p>ARN associated with the table.</p>
    pub fn get_table_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_arn
    }
    /// <p>ARN associated with the backup.</p>
    pub fn backup_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN associated with the backup.</p>
    pub fn set_backup_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_arn = input;
        self
    }
    /// <p>ARN associated with the backup.</p>
    pub fn get_backup_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_arn
    }
    /// <p>Name of the specified backup.</p>
    pub fn backup_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the specified backup.</p>
    pub fn set_backup_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_name = input;
        self
    }
    /// <p>Name of the specified backup.</p>
    pub fn get_backup_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_name
    }
    /// <p>Time at which the backup was created.</p>
    pub fn backup_creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.backup_creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time at which the backup was created.</p>
    pub fn set_backup_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.backup_creation_date_time = input;
        self
    }
    /// <p>Time at which the backup was created.</p>
    pub fn get_backup_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.backup_creation_date_time
    }
    /// <p>Time at which the automatic on-demand backup created by DynamoDB will expire. This <code>SYSTEM</code> on-demand backup expires automatically 35 days after its creation.</p>
    pub fn backup_expiry_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.backup_expiry_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time at which the automatic on-demand backup created by DynamoDB will expire. This <code>SYSTEM</code> on-demand backup expires automatically 35 days after its creation.</p>
    pub fn set_backup_expiry_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.backup_expiry_date_time = input;
        self
    }
    /// <p>Time at which the automatic on-demand backup created by DynamoDB will expire. This <code>SYSTEM</code> on-demand backup expires automatically 35 days after its creation.</p>
    pub fn get_backup_expiry_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.backup_expiry_date_time
    }
    /// <p>Backup can be in one of the following states: CREATING, ACTIVE, DELETED.</p>
    pub fn backup_status(mut self, input: crate::types::BackupStatus) -> Self {
        self.backup_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Backup can be in one of the following states: CREATING, ACTIVE, DELETED.</p>
    pub fn set_backup_status(mut self, input: ::std::option::Option<crate::types::BackupStatus>) -> Self {
        self.backup_status = input;
        self
    }
    /// <p>Backup can be in one of the following states: CREATING, ACTIVE, DELETED.</p>
    pub fn get_backup_status(&self) -> &::std::option::Option<crate::types::BackupStatus> {
        &self.backup_status
    }
    /// <p>BackupType:</p>
    /// <ul>
    /// <li>
    /// <p><code>USER</code> - You create and manage these using the on-demand backup feature.</p></li>
    /// <li>
    /// <p><code>SYSTEM</code> - If you delete a table with point-in-time recovery enabled, a <code>SYSTEM</code> backup is automatically created and is retained for 35 days (at no additional cost). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.</p></li>
    /// <li>
    /// <p><code>AWS_BACKUP</code> - On-demand backup created by you from Backup service.</p></li>
    /// </ul>
    pub fn backup_type(mut self, input: crate::types::BackupType) -> Self {
        self.backup_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>BackupType:</p>
    /// <ul>
    /// <li>
    /// <p><code>USER</code> - You create and manage these using the on-demand backup feature.</p></li>
    /// <li>
    /// <p><code>SYSTEM</code> - If you delete a table with point-in-time recovery enabled, a <code>SYSTEM</code> backup is automatically created and is retained for 35 days (at no additional cost). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.</p></li>
    /// <li>
    /// <p><code>AWS_BACKUP</code> - On-demand backup created by you from Backup service.</p></li>
    /// </ul>
    pub fn set_backup_type(mut self, input: ::std::option::Option<crate::types::BackupType>) -> Self {
        self.backup_type = input;
        self
    }
    /// <p>BackupType:</p>
    /// <ul>
    /// <li>
    /// <p><code>USER</code> - You create and manage these using the on-demand backup feature.</p></li>
    /// <li>
    /// <p><code>SYSTEM</code> - If you delete a table with point-in-time recovery enabled, a <code>SYSTEM</code> backup is automatically created and is retained for 35 days (at no additional cost). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.</p></li>
    /// <li>
    /// <p><code>AWS_BACKUP</code> - On-demand backup created by you from Backup service.</p></li>
    /// </ul>
    pub fn get_backup_type(&self) -> &::std::option::Option<crate::types::BackupType> {
        &self.backup_type
    }
    /// <p>Size of the backup in bytes.</p>
    pub fn backup_size_bytes(mut self, input: i64) -> Self {
        self.backup_size_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Size of the backup in bytes.</p>
    pub fn set_backup_size_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.backup_size_bytes = input;
        self
    }
    /// <p>Size of the backup in bytes.</p>
    pub fn get_backup_size_bytes(&self) -> &::std::option::Option<i64> {
        &self.backup_size_bytes
    }
    /// Consumes the builder and constructs a [`BackupSummary`](crate::types::BackupSummary).
    pub fn build(self) -> crate::types::BackupSummary {
        crate::types::BackupSummary {
            table_name: self.table_name,
            table_id: self.table_id,
            table_arn: self.table_arn,
            backup_arn: self.backup_arn,
            backup_name: self.backup_name,
            backup_creation_date_time: self.backup_creation_date_time,
            backup_expiry_date_time: self.backup_expiry_date_time,
            backup_status: self.backup_status,
            backup_type: self.backup_type,
            backup_size_bytes: self.backup_size_bytes,
        }
    }
}
