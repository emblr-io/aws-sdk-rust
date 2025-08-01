// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the backup plan and rule that Backup used to initiate the recovery point backup.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsBackupRecoveryPointCreatedByDetails {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan.</p>
    pub backup_plan_arn: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies a backup plan.</p>
    pub backup_plan_id: ::std::option::Option<::std::string::String>,
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub backup_plan_version: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies a rule used to schedule the backup of a selection of resources.</p>
    pub backup_rule_id: ::std::option::Option<::std::string::String>,
}
impl AwsBackupRecoveryPointCreatedByDetails {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan.</p>
    pub fn backup_plan_arn(&self) -> ::std::option::Option<&str> {
        self.backup_plan_arn.as_deref()
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn backup_plan_id(&self) -> ::std::option::Option<&str> {
        self.backup_plan_id.as_deref()
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn backup_plan_version(&self) -> ::std::option::Option<&str> {
        self.backup_plan_version.as_deref()
    }
    /// <p>Uniquely identifies a rule used to schedule the backup of a selection of resources.</p>
    pub fn backup_rule_id(&self) -> ::std::option::Option<&str> {
        self.backup_rule_id.as_deref()
    }
}
impl AwsBackupRecoveryPointCreatedByDetails {
    /// Creates a new builder-style object to manufacture [`AwsBackupRecoveryPointCreatedByDetails`](crate::types::AwsBackupRecoveryPointCreatedByDetails).
    pub fn builder() -> crate::types::builders::AwsBackupRecoveryPointCreatedByDetailsBuilder {
        crate::types::builders::AwsBackupRecoveryPointCreatedByDetailsBuilder::default()
    }
}

/// A builder for [`AwsBackupRecoveryPointCreatedByDetails`](crate::types::AwsBackupRecoveryPointCreatedByDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsBackupRecoveryPointCreatedByDetailsBuilder {
    pub(crate) backup_plan_arn: ::std::option::Option<::std::string::String>,
    pub(crate) backup_plan_id: ::std::option::Option<::std::string::String>,
    pub(crate) backup_plan_version: ::std::option::Option<::std::string::String>,
    pub(crate) backup_rule_id: ::std::option::Option<::std::string::String>,
}
impl AwsBackupRecoveryPointCreatedByDetailsBuilder {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan.</p>
    pub fn backup_plan_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan.</p>
    pub fn set_backup_plan_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_arn = input;
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan.</p>
    pub fn get_backup_plan_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_arn
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn backup_plan_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn set_backup_plan_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_id = input;
        self
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn get_backup_plan_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_id
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn backup_plan_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn set_backup_plan_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_version = input;
        self
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn get_backup_plan_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_version
    }
    /// <p>Uniquely identifies a rule used to schedule the backup of a selection of resources.</p>
    pub fn backup_rule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_rule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies a rule used to schedule the backup of a selection of resources.</p>
    pub fn set_backup_rule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_rule_id = input;
        self
    }
    /// <p>Uniquely identifies a rule used to schedule the backup of a selection of resources.</p>
    pub fn get_backup_rule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_rule_id
    }
    /// Consumes the builder and constructs a [`AwsBackupRecoveryPointCreatedByDetails`](crate::types::AwsBackupRecoveryPointCreatedByDetails).
    pub fn build(self) -> crate::types::AwsBackupRecoveryPointCreatedByDetails {
        crate::types::AwsBackupRecoveryPointCreatedByDetails {
            backup_plan_arn: self.backup_plan_arn,
            backup_plan_id: self.backup_plan_id,
            backup_plan_version: self.backup_plan_version,
            backup_rule_id: self.backup_rule_id,
        }
    }
}
