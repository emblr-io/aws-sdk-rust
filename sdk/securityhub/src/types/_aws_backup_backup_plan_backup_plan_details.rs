// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about an Backup backup plan and an array of <code>BackupRule</code> objects, each of which specifies a backup rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsBackupBackupPlanBackupPlanDetails {
    /// <p>The display name of a backup plan.</p>
    pub backup_plan_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of backup options for each resource type.</p>
    pub advanced_backup_settings: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails>>,
    /// <p>An array of <code>BackupRule</code> objects, each of which specifies a scheduled task that is used to back up a selection of resources.</p>
    pub backup_plan_rule: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanRuleDetails>>,
}
impl AwsBackupBackupPlanBackupPlanDetails {
    /// <p>The display name of a backup plan.</p>
    pub fn backup_plan_name(&self) -> ::std::option::Option<&str> {
        self.backup_plan_name.as_deref()
    }
    /// <p>A list of backup options for each resource type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.advanced_backup_settings.is_none()`.
    pub fn advanced_backup_settings(&self) -> &[crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails] {
        self.advanced_backup_settings.as_deref().unwrap_or_default()
    }
    /// <p>An array of <code>BackupRule</code> objects, each of which specifies a scheduled task that is used to back up a selection of resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.backup_plan_rule.is_none()`.
    pub fn backup_plan_rule(&self) -> &[crate::types::AwsBackupBackupPlanRuleDetails] {
        self.backup_plan_rule.as_deref().unwrap_or_default()
    }
}
impl AwsBackupBackupPlanBackupPlanDetails {
    /// Creates a new builder-style object to manufacture [`AwsBackupBackupPlanBackupPlanDetails`](crate::types::AwsBackupBackupPlanBackupPlanDetails).
    pub fn builder() -> crate::types::builders::AwsBackupBackupPlanBackupPlanDetailsBuilder {
        crate::types::builders::AwsBackupBackupPlanBackupPlanDetailsBuilder::default()
    }
}

/// A builder for [`AwsBackupBackupPlanBackupPlanDetails`](crate::types::AwsBackupBackupPlanBackupPlanDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsBackupBackupPlanBackupPlanDetailsBuilder {
    pub(crate) backup_plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) advanced_backup_settings: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails>>,
    pub(crate) backup_plan_rule: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanRuleDetails>>,
}
impl AwsBackupBackupPlanBackupPlanDetailsBuilder {
    /// <p>The display name of a backup plan.</p>
    pub fn backup_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of a backup plan.</p>
    pub fn set_backup_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_name = input;
        self
    }
    /// <p>The display name of a backup plan.</p>
    pub fn get_backup_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_name
    }
    /// Appends an item to `advanced_backup_settings`.
    ///
    /// To override the contents of this collection use [`set_advanced_backup_settings`](Self::set_advanced_backup_settings).
    ///
    /// <p>A list of backup options for each resource type.</p>
    pub fn advanced_backup_settings(mut self, input: crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails) -> Self {
        let mut v = self.advanced_backup_settings.unwrap_or_default();
        v.push(input);
        self.advanced_backup_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of backup options for each resource type.</p>
    pub fn set_advanced_backup_settings(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails>>,
    ) -> Self {
        self.advanced_backup_settings = input;
        self
    }
    /// <p>A list of backup options for each resource type.</p>
    pub fn get_advanced_backup_settings(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanAdvancedBackupSettingsDetails>> {
        &self.advanced_backup_settings
    }
    /// Appends an item to `backup_plan_rule`.
    ///
    /// To override the contents of this collection use [`set_backup_plan_rule`](Self::set_backup_plan_rule).
    ///
    /// <p>An array of <code>BackupRule</code> objects, each of which specifies a scheduled task that is used to back up a selection of resources.</p>
    pub fn backup_plan_rule(mut self, input: crate::types::AwsBackupBackupPlanRuleDetails) -> Self {
        let mut v = self.backup_plan_rule.unwrap_or_default();
        v.push(input);
        self.backup_plan_rule = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>BackupRule</code> objects, each of which specifies a scheduled task that is used to back up a selection of resources.</p>
    pub fn set_backup_plan_rule(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanRuleDetails>>) -> Self {
        self.backup_plan_rule = input;
        self
    }
    /// <p>An array of <code>BackupRule</code> objects, each of which specifies a scheduled task that is used to back up a selection of resources.</p>
    pub fn get_backup_plan_rule(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsBackupBackupPlanRuleDetails>> {
        &self.backup_plan_rule
    }
    /// Consumes the builder and constructs a [`AwsBackupBackupPlanBackupPlanDetails`](crate::types::AwsBackupBackupPlanBackupPlanDetails).
    pub fn build(self) -> crate::types::AwsBackupBackupPlanBackupPlanDetails {
        crate::types::AwsBackupBackupPlanBackupPlanDetails {
            backup_plan_name: self.backup_plan_name,
            advanced_backup_settings: self.advanced_backup_settings,
            backup_plan_rule: self.backup_plan_rule,
        }
    }
}
