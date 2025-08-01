// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains metadata about a backup plan.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BackupPlansListMember {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, <code>arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50</code>.</p>
    pub backup_plan_arn: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies a backup plan.</p>
    pub backup_plan_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of <code>DeletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub deletion_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>The display name of a saved backup plan.</p>
    pub backup_plan_name: ::std::option::Option<::std::string::String>,
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional.</p>
    /// <p>If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters.</p>
    pub creator_request_id: ::std::option::Option<::std::string::String>,
    /// <p>The last time this backup plan was run. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of <code>LastExecutionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub last_execution_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Contains a list of <code>BackupOptions</code> for a resource type.</p>
    pub advanced_backup_settings: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedBackupSetting>>,
}
impl BackupPlansListMember {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, <code>arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50</code>.</p>
    pub fn backup_plan_arn(&self) -> ::std::option::Option<&str> {
        self.backup_plan_arn.as_deref()
    }
    /// <p>Uniquely identifies a backup plan.</p>
    pub fn backup_plan_id(&self) -> ::std::option::Option<&str> {
        self.backup_plan_id.as_deref()
    }
    /// <p>The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of <code>DeletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn deletion_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.deletion_date.as_ref()
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>The display name of a saved backup plan.</p>
    pub fn backup_plan_name(&self) -> ::std::option::Option<&str> {
        self.backup_plan_name.as_deref()
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional.</p>
    /// <p>If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters.</p>
    pub fn creator_request_id(&self) -> ::std::option::Option<&str> {
        self.creator_request_id.as_deref()
    }
    /// <p>The last time this backup plan was run. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of <code>LastExecutionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn last_execution_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_execution_date.as_ref()
    }
    /// <p>Contains a list of <code>BackupOptions</code> for a resource type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.advanced_backup_settings.is_none()`.
    pub fn advanced_backup_settings(&self) -> &[crate::types::AdvancedBackupSetting] {
        self.advanced_backup_settings.as_deref().unwrap_or_default()
    }
}
impl BackupPlansListMember {
    /// Creates a new builder-style object to manufacture [`BackupPlansListMember`](crate::types::BackupPlansListMember).
    pub fn builder() -> crate::types::builders::BackupPlansListMemberBuilder {
        crate::types::builders::BackupPlansListMemberBuilder::default()
    }
}

/// A builder for [`BackupPlansListMember`](crate::types::BackupPlansListMember).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BackupPlansListMemberBuilder {
    pub(crate) backup_plan_arn: ::std::option::Option<::std::string::String>,
    pub(crate) backup_plan_id: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) deletion_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) backup_plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) creator_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_execution_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) advanced_backup_settings: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedBackupSetting>>,
}
impl BackupPlansListMemberBuilder {
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, <code>arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50</code>.</p>
    pub fn backup_plan_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, <code>arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50</code>.</p>
    pub fn set_backup_plan_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_arn = input;
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a backup plan; for example, <code>arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50</code>.</p>
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
    /// <p>The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time a resource backup plan is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of <code>DeletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn deletion_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.deletion_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of <code>DeletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_deletion_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.deletion_date = input;
        self
    }
    /// <p>The date and time a backup plan is deleted, in Unix format and Coordinated Universal Time (UTC). The value of <code>DeletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_deletion_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.deletion_date
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long. Version IDs cannot be edited.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// <p>The display name of a saved backup plan.</p>
    pub fn backup_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of a saved backup plan.</p>
    pub fn set_backup_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_plan_name = input;
        self
    }
    /// <p>The display name of a saved backup plan.</p>
    pub fn get_backup_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_plan_name
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional.</p>
    /// <p>If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters.</p>
    pub fn creator_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional.</p>
    /// <p>If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters.</p>
    pub fn set_creator_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_request_id = input;
        self
    }
    /// <p>A unique string that identifies the request and allows failed requests to be retried without the risk of running the operation twice. This parameter is optional.</p>
    /// <p>If used, this parameter must contain 1 to 50 alphanumeric or '-_.' characters.</p>
    pub fn get_creator_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_request_id
    }
    /// <p>The last time this backup plan was run. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of <code>LastExecutionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn last_execution_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_execution_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time this backup plan was run. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of <code>LastExecutionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_last_execution_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_execution_date = input;
        self
    }
    /// <p>The last time this backup plan was run. A date and time, in Unix format and Coordinated Universal Time (UTC). The value of <code>LastExecutionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_last_execution_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_execution_date
    }
    /// Appends an item to `advanced_backup_settings`.
    ///
    /// To override the contents of this collection use [`set_advanced_backup_settings`](Self::set_advanced_backup_settings).
    ///
    /// <p>Contains a list of <code>BackupOptions</code> for a resource type.</p>
    pub fn advanced_backup_settings(mut self, input: crate::types::AdvancedBackupSetting) -> Self {
        let mut v = self.advanced_backup_settings.unwrap_or_default();
        v.push(input);
        self.advanced_backup_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains a list of <code>BackupOptions</code> for a resource type.</p>
    pub fn set_advanced_backup_settings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedBackupSetting>>) -> Self {
        self.advanced_backup_settings = input;
        self
    }
    /// <p>Contains a list of <code>BackupOptions</code> for a resource type.</p>
    pub fn get_advanced_backup_settings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdvancedBackupSetting>> {
        &self.advanced_backup_settings
    }
    /// Consumes the builder and constructs a [`BackupPlansListMember`](crate::types::BackupPlansListMember).
    pub fn build(self) -> crate::types::BackupPlansListMember {
        crate::types::BackupPlansListMember {
            backup_plan_arn: self.backup_plan_arn,
            backup_plan_id: self.backup_plan_id,
            creation_date: self.creation_date,
            deletion_date: self.deletion_date,
            version_id: self.version_id,
            backup_plan_name: self.backup_plan_name,
            creator_request_id: self.creator_request_id,
            last_execution_date: self.last_execution_date,
            advanced_backup_settings: self.advanced_backup_settings,
        }
    }
}
