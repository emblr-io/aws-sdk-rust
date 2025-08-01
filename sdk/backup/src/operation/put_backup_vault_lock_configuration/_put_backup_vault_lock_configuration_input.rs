// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBackupVaultLockConfigurationInput {
    /// <p>The Backup Vault Lock configuration that specifies the name of the backup vault it protects.</p>
    pub backup_vault_name: ::std::option::Option<::std::string::String>,
    /// <p>The Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).</p>
    /// <p>This parameter is required when a vault lock is created through CloudFormation; otherwise, this parameter is optional. If this parameter is not specified, Vault Lock will not enforce a minimum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. The shortest minimum retention period you can specify is 1 day. Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub min_retention_days: ::std::option::Option<i64>,
    /// <p>The Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).</p>
    /// <p>If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. The longest maximum retention period you can specify is 36500 days (approximately 100 years). Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub max_retention_days: ::std::option::Option<i64>,
    /// <p>The Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting <code>ChangeableForDays</code> to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.</p>
    /// <p>Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set <code>ChangeableForDays</code> to 3 or greater.</p>
    /// <p>Before the lock date, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code>. On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.</p>
    /// <p>If this parameter is not specified, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code> at any time.</p>
    pub changeable_for_days: ::std::option::Option<i64>,
}
impl PutBackupVaultLockConfigurationInput {
    /// <p>The Backup Vault Lock configuration that specifies the name of the backup vault it protects.</p>
    pub fn backup_vault_name(&self) -> ::std::option::Option<&str> {
        self.backup_vault_name.as_deref()
    }
    /// <p>The Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).</p>
    /// <p>This parameter is required when a vault lock is created through CloudFormation; otherwise, this parameter is optional. If this parameter is not specified, Vault Lock will not enforce a minimum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. The shortest minimum retention period you can specify is 1 day. Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn min_retention_days(&self) -> ::std::option::Option<i64> {
        self.min_retention_days
    }
    /// <p>The Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).</p>
    /// <p>If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. The longest maximum retention period you can specify is 36500 days (approximately 100 years). Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn max_retention_days(&self) -> ::std::option::Option<i64> {
        self.max_retention_days
    }
    /// <p>The Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting <code>ChangeableForDays</code> to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.</p>
    /// <p>Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set <code>ChangeableForDays</code> to 3 or greater.</p>
    /// <p>Before the lock date, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code>. On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.</p>
    /// <p>If this parameter is not specified, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code> at any time.</p>
    pub fn changeable_for_days(&self) -> ::std::option::Option<i64> {
        self.changeable_for_days
    }
}
impl PutBackupVaultLockConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutBackupVaultLockConfigurationInput`](crate::operation::put_backup_vault_lock_configuration::PutBackupVaultLockConfigurationInput).
    pub fn builder() -> crate::operation::put_backup_vault_lock_configuration::builders::PutBackupVaultLockConfigurationInputBuilder {
        crate::operation::put_backup_vault_lock_configuration::builders::PutBackupVaultLockConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutBackupVaultLockConfigurationInput`](crate::operation::put_backup_vault_lock_configuration::PutBackupVaultLockConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBackupVaultLockConfigurationInputBuilder {
    pub(crate) backup_vault_name: ::std::option::Option<::std::string::String>,
    pub(crate) min_retention_days: ::std::option::Option<i64>,
    pub(crate) max_retention_days: ::std::option::Option<i64>,
    pub(crate) changeable_for_days: ::std::option::Option<i64>,
}
impl PutBackupVaultLockConfigurationInputBuilder {
    /// <p>The Backup Vault Lock configuration that specifies the name of the backup vault it protects.</p>
    /// This field is required.
    pub fn backup_vault_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_vault_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the name of the backup vault it protects.</p>
    pub fn set_backup_vault_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_vault_name = input;
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the name of the backup vault it protects.</p>
    pub fn get_backup_vault_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_vault_name
    }
    /// <p>The Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).</p>
    /// <p>This parameter is required when a vault lock is created through CloudFormation; otherwise, this parameter is optional. If this parameter is not specified, Vault Lock will not enforce a minimum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. The shortest minimum retention period you can specify is 1 day. Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn min_retention_days(mut self, input: i64) -> Self {
        self.min_retention_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).</p>
    /// <p>This parameter is required when a vault lock is created through CloudFormation; otherwise, this parameter is optional. If this parameter is not specified, Vault Lock will not enforce a minimum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. The shortest minimum retention period you can specify is 1 day. Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn set_min_retention_days(mut self, input: ::std::option::Option<i64>) -> Self {
        self.min_retention_days = input;
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).</p>
    /// <p>This parameter is required when a vault lock is created through CloudFormation; otherwise, this parameter is optional. If this parameter is not specified, Vault Lock will not enforce a minimum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. The shortest minimum retention period you can specify is 1 day. Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn get_min_retention_days(&self) -> &::std::option::Option<i64> {
        &self.min_retention_days
    }
    /// <p>The Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).</p>
    /// <p>If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. The longest maximum retention period you can specify is 36500 days (approximately 100 years). Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn max_retention_days(mut self, input: i64) -> Self {
        self.max_retention_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).</p>
    /// <p>If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. The longest maximum retention period you can specify is 36500 days (approximately 100 years). Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn set_max_retention_days(mut self, input: ::std::option::Option<i64>) -> Self {
        self.max_retention_days = input;
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).</p>
    /// <p>If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.</p>
    /// <p>If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. The longest maximum retention period you can specify is 36500 days (approximately 100 years). Recovery points already saved in the vault prior to Vault Lock are not affected.</p>
    pub fn get_max_retention_days(&self) -> &::std::option::Option<i64> {
        &self.max_retention_days
    }
    /// <p>The Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting <code>ChangeableForDays</code> to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.</p>
    /// <p>Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set <code>ChangeableForDays</code> to 3 or greater.</p>
    /// <p>Before the lock date, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code>. On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.</p>
    /// <p>If this parameter is not specified, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code> at any time.</p>
    pub fn changeable_for_days(mut self, input: i64) -> Self {
        self.changeable_for_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting <code>ChangeableForDays</code> to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.</p>
    /// <p>Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set <code>ChangeableForDays</code> to 3 or greater.</p>
    /// <p>Before the lock date, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code>. On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.</p>
    /// <p>If this parameter is not specified, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code> at any time.</p>
    pub fn set_changeable_for_days(mut self, input: ::std::option::Option<i64>) -> Self {
        self.changeable_for_days = input;
        self
    }
    /// <p>The Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting <code>ChangeableForDays</code> to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.</p>
    /// <p>Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set <code>ChangeableForDays</code> to 3 or greater.</p>
    /// <p>Before the lock date, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code>. On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.</p>
    /// <p>If this parameter is not specified, you can delete Vault Lock from the vault using <code>DeleteBackupVaultLockConfiguration</code> or change the Vault Lock configuration using <code>PutBackupVaultLockConfiguration</code> at any time.</p>
    pub fn get_changeable_for_days(&self) -> &::std::option::Option<i64> {
        &self.changeable_for_days
    }
    /// Consumes the builder and constructs a [`PutBackupVaultLockConfigurationInput`](crate::operation::put_backup_vault_lock_configuration::PutBackupVaultLockConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_backup_vault_lock_configuration::PutBackupVaultLockConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_backup_vault_lock_configuration::PutBackupVaultLockConfigurationInput {
                backup_vault_name: self.backup_vault_name,
                min_retention_days: self.min_retention_days,
                max_retention_days: self.max_retention_days,
                changeable_for_days: self.changeable_for_days,
            },
        )
    }
}
