// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains metadata about a restore job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreJobsListMember {
    /// <p>The account ID that owns the restore job.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>Uniquely identifies the job that restores a recovery point.</p>
    pub restore_job_id: ::std::option::Option<::std::string::String>,
    /// <p>An ARN that uniquely identifies a recovery point; for example, <code>arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45</code>.</p>
    pub recovery_point_arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of <code>CompletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub completion_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A status code specifying the state of the job initiated by Backup to restore a recovery point.</p>
    pub status: ::std::option::Option<crate::types::RestoreJobStatus>,
    /// <p>A detailed message explaining the status of the job to restore a recovery point.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>Contains an estimated percentage complete of a job at the time the job status was queried.</p>
    pub percent_done: ::std::option::Option<::std::string::String>,
    /// <p>The size, in bytes, of the restored resource.</p>
    pub backup_size_in_bytes: ::std::option::Option<i64>,
    /// <p>The IAM role ARN used to create the target recovery point; for example, <code>arn:aws:iam::123456789012:role/S3Access</code>.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The amount of time in minutes that a job restoring a recovery point is expected to take.</p>
    pub expected_completion_time_minutes: ::std::option::Option<i64>,
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub created_resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>The date on which a recovery point was created.</p>
    pub recovery_point_creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Contains identifying information about the creation of a restore job.</p>
    pub created_by: ::std::option::Option<crate::types::RestoreJobCreator>,
    /// <p>The status of validation run on the indicated restore job.</p>
    pub validation_status: ::std::option::Option<crate::types::RestoreValidationStatus>,
    /// <p>This describes the status of validation run on the indicated restore job.</p>
    pub validation_status_message: ::std::option::Option<::std::string::String>,
    /// <p>This notes the status of the data generated by the restore test. The status may be <code>Deleting</code>, <code>Failed</code>, or <code>Successful</code>.</p>
    pub deletion_status: ::std::option::Option<crate::types::RestoreDeletionStatus>,
    /// <p>This describes the restore job deletion status.</p>
    pub deletion_status_message: ::std::option::Option<::std::string::String>,
}
impl RestoreJobsListMember {
    /// <p>The account ID that owns the restore job.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>Uniquely identifies the job that restores a recovery point.</p>
    pub fn restore_job_id(&self) -> ::std::option::Option<&str> {
        self.restore_job_id.as_deref()
    }
    /// <p>An ARN that uniquely identifies a recovery point; for example, <code>arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45</code>.</p>
    pub fn recovery_point_arn(&self) -> ::std::option::Option<&str> {
        self.recovery_point_arn.as_deref()
    }
    /// <p>The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of <code>CompletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn completion_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_date.as_ref()
    }
    /// <p>A status code specifying the state of the job initiated by Backup to restore a recovery point.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::RestoreJobStatus> {
        self.status.as_ref()
    }
    /// <p>A detailed message explaining the status of the job to restore a recovery point.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>Contains an estimated percentage complete of a job at the time the job status was queried.</p>
    pub fn percent_done(&self) -> ::std::option::Option<&str> {
        self.percent_done.as_deref()
    }
    /// <p>The size, in bytes, of the restored resource.</p>
    pub fn backup_size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.backup_size_in_bytes
    }
    /// <p>The IAM role ARN used to create the target recovery point; for example, <code>arn:aws:iam::123456789012:role/S3Access</code>.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
    /// <p>The amount of time in minutes that a job restoring a recovery point is expected to take.</p>
    pub fn expected_completion_time_minutes(&self) -> ::std::option::Option<i64> {
        self.expected_completion_time_minutes
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn created_resource_arn(&self) -> ::std::option::Option<&str> {
        self.created_resource_arn.as_deref()
    }
    /// <p>The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>The date on which a recovery point was created.</p>
    pub fn recovery_point_creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.recovery_point_creation_date.as_ref()
    }
    /// <p>Contains identifying information about the creation of a restore job.</p>
    pub fn created_by(&self) -> ::std::option::Option<&crate::types::RestoreJobCreator> {
        self.created_by.as_ref()
    }
    /// <p>The status of validation run on the indicated restore job.</p>
    pub fn validation_status(&self) -> ::std::option::Option<&crate::types::RestoreValidationStatus> {
        self.validation_status.as_ref()
    }
    /// <p>This describes the status of validation run on the indicated restore job.</p>
    pub fn validation_status_message(&self) -> ::std::option::Option<&str> {
        self.validation_status_message.as_deref()
    }
    /// <p>This notes the status of the data generated by the restore test. The status may be <code>Deleting</code>, <code>Failed</code>, or <code>Successful</code>.</p>
    pub fn deletion_status(&self) -> ::std::option::Option<&crate::types::RestoreDeletionStatus> {
        self.deletion_status.as_ref()
    }
    /// <p>This describes the restore job deletion status.</p>
    pub fn deletion_status_message(&self) -> ::std::option::Option<&str> {
        self.deletion_status_message.as_deref()
    }
}
impl RestoreJobsListMember {
    /// Creates a new builder-style object to manufacture [`RestoreJobsListMember`](crate::types::RestoreJobsListMember).
    pub fn builder() -> crate::types::builders::RestoreJobsListMemberBuilder {
        crate::types::builders::RestoreJobsListMemberBuilder::default()
    }
}

/// A builder for [`RestoreJobsListMember`](crate::types::RestoreJobsListMember).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestoreJobsListMemberBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) restore_job_id: ::std::option::Option<::std::string::String>,
    pub(crate) recovery_point_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completion_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::RestoreJobStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) percent_done: ::std::option::Option<::std::string::String>,
    pub(crate) backup_size_in_bytes: ::std::option::Option<i64>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) expected_completion_time_minutes: ::std::option::Option<i64>,
    pub(crate) created_resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) recovery_point_creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<crate::types::RestoreJobCreator>,
    pub(crate) validation_status: ::std::option::Option<crate::types::RestoreValidationStatus>,
    pub(crate) validation_status_message: ::std::option::Option<::std::string::String>,
    pub(crate) deletion_status: ::std::option::Option<crate::types::RestoreDeletionStatus>,
    pub(crate) deletion_status_message: ::std::option::Option<::std::string::String>,
}
impl RestoreJobsListMemberBuilder {
    /// <p>The account ID that owns the restore job.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID that owns the restore job.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The account ID that owns the restore job.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>Uniquely identifies the job that restores a recovery point.</p>
    pub fn restore_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restore_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Uniquely identifies the job that restores a recovery point.</p>
    pub fn set_restore_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restore_job_id = input;
        self
    }
    /// <p>Uniquely identifies the job that restores a recovery point.</p>
    pub fn get_restore_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.restore_job_id
    }
    /// <p>An ARN that uniquely identifies a recovery point; for example, <code>arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45</code>.</p>
    pub fn recovery_point_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recovery_point_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ARN that uniquely identifies a recovery point; for example, <code>arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45</code>.</p>
    pub fn set_recovery_point_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recovery_point_arn = input;
        self
    }
    /// <p>An ARN that uniquely identifies a recovery point; for example, <code>arn:aws:backup:us-east-1:123456789012:recovery-point:1EB3B5E7-9EB0-435A-A80B-108B488B0D45</code>.</p>
    pub fn get_recovery_point_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.recovery_point_arn
    }
    /// <p>The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time a restore job is created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of <code>CompletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn completion_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of <code>CompletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn set_completion_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_date = input;
        self
    }
    /// <p>The date and time a job to restore a recovery point is completed, in Unix format and Coordinated Universal Time (UTC). The value of <code>CompletionDate</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087 AM.</p>
    pub fn get_completion_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_date
    }
    /// <p>A status code specifying the state of the job initiated by Backup to restore a recovery point.</p>
    pub fn status(mut self, input: crate::types::RestoreJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A status code specifying the state of the job initiated by Backup to restore a recovery point.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::RestoreJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>A status code specifying the state of the job initiated by Backup to restore a recovery point.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::RestoreJobStatus> {
        &self.status
    }
    /// <p>A detailed message explaining the status of the job to restore a recovery point.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A detailed message explaining the status of the job to restore a recovery point.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A detailed message explaining the status of the job to restore a recovery point.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>Contains an estimated percentage complete of a job at the time the job status was queried.</p>
    pub fn percent_done(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.percent_done = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains an estimated percentage complete of a job at the time the job status was queried.</p>
    pub fn set_percent_done(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.percent_done = input;
        self
    }
    /// <p>Contains an estimated percentage complete of a job at the time the job status was queried.</p>
    pub fn get_percent_done(&self) -> &::std::option::Option<::std::string::String> {
        &self.percent_done
    }
    /// <p>The size, in bytes, of the restored resource.</p>
    pub fn backup_size_in_bytes(mut self, input: i64) -> Self {
        self.backup_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size, in bytes, of the restored resource.</p>
    pub fn set_backup_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.backup_size_in_bytes = input;
        self
    }
    /// <p>The size, in bytes, of the restored resource.</p>
    pub fn get_backup_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.backup_size_in_bytes
    }
    /// <p>The IAM role ARN used to create the target recovery point; for example, <code>arn:aws:iam::123456789012:role/S3Access</code>.</p>
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role ARN used to create the target recovery point; for example, <code>arn:aws:iam::123456789012:role/S3Access</code>.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>The IAM role ARN used to create the target recovery point; for example, <code>arn:aws:iam::123456789012:role/S3Access</code>.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// <p>The amount of time in minutes that a job restoring a recovery point is expected to take.</p>
    pub fn expected_completion_time_minutes(mut self, input: i64) -> Self {
        self.expected_completion_time_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time in minutes that a job restoring a recovery point is expected to take.</p>
    pub fn set_expected_completion_time_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.expected_completion_time_minutes = input;
        self
    }
    /// <p>The amount of time in minutes that a job restoring a recovery point is expected to take.</p>
    pub fn get_expected_completion_time_minutes(&self) -> &::std::option::Option<i64> {
        &self.expected_completion_time_minutes
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn created_resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn set_created_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_resource_arn = input;
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies a resource. The format of the ARN depends on the resource type.</p>
    pub fn get_created_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_resource_arn
    }
    /// <p>The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2.</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type of the listed restore jobs; for example, an Amazon Elastic Block Store (Amazon EBS) volume or an Amazon Relational Database Service (Amazon RDS) database. For Windows Volume Shadow Copy Service (VSS) backups, the only supported resource type is Amazon EC2.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>The date on which a recovery point was created.</p>
    pub fn recovery_point_creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.recovery_point_creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date on which a recovery point was created.</p>
    pub fn set_recovery_point_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.recovery_point_creation_date = input;
        self
    }
    /// <p>The date on which a recovery point was created.</p>
    pub fn get_recovery_point_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.recovery_point_creation_date
    }
    /// <p>Contains identifying information about the creation of a restore job.</p>
    pub fn created_by(mut self, input: crate::types::RestoreJobCreator) -> Self {
        self.created_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains identifying information about the creation of a restore job.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<crate::types::RestoreJobCreator>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>Contains identifying information about the creation of a restore job.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<crate::types::RestoreJobCreator> {
        &self.created_by
    }
    /// <p>The status of validation run on the indicated restore job.</p>
    pub fn validation_status(mut self, input: crate::types::RestoreValidationStatus) -> Self {
        self.validation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of validation run on the indicated restore job.</p>
    pub fn set_validation_status(mut self, input: ::std::option::Option<crate::types::RestoreValidationStatus>) -> Self {
        self.validation_status = input;
        self
    }
    /// <p>The status of validation run on the indicated restore job.</p>
    pub fn get_validation_status(&self) -> &::std::option::Option<crate::types::RestoreValidationStatus> {
        &self.validation_status
    }
    /// <p>This describes the status of validation run on the indicated restore job.</p>
    pub fn validation_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.validation_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This describes the status of validation run on the indicated restore job.</p>
    pub fn set_validation_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.validation_status_message = input;
        self
    }
    /// <p>This describes the status of validation run on the indicated restore job.</p>
    pub fn get_validation_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.validation_status_message
    }
    /// <p>This notes the status of the data generated by the restore test. The status may be <code>Deleting</code>, <code>Failed</code>, or <code>Successful</code>.</p>
    pub fn deletion_status(mut self, input: crate::types::RestoreDeletionStatus) -> Self {
        self.deletion_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This notes the status of the data generated by the restore test. The status may be <code>Deleting</code>, <code>Failed</code>, or <code>Successful</code>.</p>
    pub fn set_deletion_status(mut self, input: ::std::option::Option<crate::types::RestoreDeletionStatus>) -> Self {
        self.deletion_status = input;
        self
    }
    /// <p>This notes the status of the data generated by the restore test. The status may be <code>Deleting</code>, <code>Failed</code>, or <code>Successful</code>.</p>
    pub fn get_deletion_status(&self) -> &::std::option::Option<crate::types::RestoreDeletionStatus> {
        &self.deletion_status
    }
    /// <p>This describes the restore job deletion status.</p>
    pub fn deletion_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deletion_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This describes the restore job deletion status.</p>
    pub fn set_deletion_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deletion_status_message = input;
        self
    }
    /// <p>This describes the restore job deletion status.</p>
    pub fn get_deletion_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.deletion_status_message
    }
    /// Consumes the builder and constructs a [`RestoreJobsListMember`](crate::types::RestoreJobsListMember).
    pub fn build(self) -> crate::types::RestoreJobsListMember {
        crate::types::RestoreJobsListMember {
            account_id: self.account_id,
            restore_job_id: self.restore_job_id,
            recovery_point_arn: self.recovery_point_arn,
            creation_date: self.creation_date,
            completion_date: self.completion_date,
            status: self.status,
            status_message: self.status_message,
            percent_done: self.percent_done,
            backup_size_in_bytes: self.backup_size_in_bytes,
            iam_role_arn: self.iam_role_arn,
            expected_completion_time_minutes: self.expected_completion_time_minutes,
            created_resource_arn: self.created_resource_arn,
            resource_type: self.resource_type,
            recovery_point_creation_date: self.recovery_point_creation_date,
            created_by: self.created_by,
            validation_status: self.validation_status,
            validation_status_message: self.validation_status_message,
            deletion_status: self.deletion_status,
            deletion_status_message: self.deletion_status_message,
        }
    }
}
