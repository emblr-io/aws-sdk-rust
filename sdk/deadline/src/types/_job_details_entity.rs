// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The job details for a specific job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct JobDetailsEntity {
    /// <p>The job ID.</p>
    pub job_id: ::std::string::String,
    /// <p>The job attachment settings.</p>
    pub job_attachment_settings: ::std::option::Option<crate::types::JobAttachmentSettings>,
    /// <p>The user name and group that the job uses when run.</p>
    pub job_run_as_user: ::std::option::Option<crate::types::JobRunAsUser>,
    /// <p>The log group name.</p>
    pub log_group_name: ::std::string::String,
    /// <p>The queue role ARN.</p>
    pub queue_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The parameters.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    /// <p>The schema version.</p>
    pub schema_version: ::std::string::String,
    /// <p>The path mapping rules.</p>
    pub path_mapping_rules: ::std::option::Option<::std::vec::Vec<crate::types::PathMappingRule>>,
}
impl JobDetailsEntity {
    /// <p>The job ID.</p>
    pub fn job_id(&self) -> &str {
        use std::ops::Deref;
        self.job_id.deref()
    }
    /// <p>The job attachment settings.</p>
    pub fn job_attachment_settings(&self) -> ::std::option::Option<&crate::types::JobAttachmentSettings> {
        self.job_attachment_settings.as_ref()
    }
    /// <p>The user name and group that the job uses when run.</p>
    pub fn job_run_as_user(&self) -> ::std::option::Option<&crate::types::JobRunAsUser> {
        self.job_run_as_user.as_ref()
    }
    /// <p>The log group name.</p>
    pub fn log_group_name(&self) -> &str {
        use std::ops::Deref;
        self.log_group_name.deref()
    }
    /// <p>The queue role ARN.</p>
    pub fn queue_role_arn(&self) -> ::std::option::Option<&str> {
        self.queue_role_arn.as_deref()
    }
    /// <p>The parameters.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::JobParameter>> {
        self.parameters.as_ref()
    }
    /// <p>The schema version.</p>
    pub fn schema_version(&self) -> &str {
        use std::ops::Deref;
        self.schema_version.deref()
    }
    /// <p>The path mapping rules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.path_mapping_rules.is_none()`.
    pub fn path_mapping_rules(&self) -> &[crate::types::PathMappingRule] {
        self.path_mapping_rules.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for JobDetailsEntity {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("JobDetailsEntity");
        formatter.field("job_id", &self.job_id);
        formatter.field("job_attachment_settings", &self.job_attachment_settings);
        formatter.field("job_run_as_user", &self.job_run_as_user);
        formatter.field("log_group_name", &self.log_group_name);
        formatter.field("queue_role_arn", &self.queue_role_arn);
        formatter.field("parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("schema_version", &self.schema_version);
        formatter.field("path_mapping_rules", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl JobDetailsEntity {
    /// Creates a new builder-style object to manufacture [`JobDetailsEntity`](crate::types::JobDetailsEntity).
    pub fn builder() -> crate::types::builders::JobDetailsEntityBuilder {
        crate::types::builders::JobDetailsEntityBuilder::default()
    }
}

/// A builder for [`JobDetailsEntity`](crate::types::JobDetailsEntity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct JobDetailsEntityBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_attachment_settings: ::std::option::Option<crate::types::JobAttachmentSettings>,
    pub(crate) job_run_as_user: ::std::option::Option<crate::types::JobRunAsUser>,
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) queue_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    pub(crate) schema_version: ::std::option::Option<::std::string::String>,
    pub(crate) path_mapping_rules: ::std::option::Option<::std::vec::Vec<crate::types::PathMappingRule>>,
}
impl JobDetailsEntityBuilder {
    /// <p>The job ID.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job ID.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The job ID.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The job attachment settings.</p>
    pub fn job_attachment_settings(mut self, input: crate::types::JobAttachmentSettings) -> Self {
        self.job_attachment_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The job attachment settings.</p>
    pub fn set_job_attachment_settings(mut self, input: ::std::option::Option<crate::types::JobAttachmentSettings>) -> Self {
        self.job_attachment_settings = input;
        self
    }
    /// <p>The job attachment settings.</p>
    pub fn get_job_attachment_settings(&self) -> &::std::option::Option<crate::types::JobAttachmentSettings> {
        &self.job_attachment_settings
    }
    /// <p>The user name and group that the job uses when run.</p>
    pub fn job_run_as_user(mut self, input: crate::types::JobRunAsUser) -> Self {
        self.job_run_as_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user name and group that the job uses when run.</p>
    pub fn set_job_run_as_user(mut self, input: ::std::option::Option<crate::types::JobRunAsUser>) -> Self {
        self.job_run_as_user = input;
        self
    }
    /// <p>The user name and group that the job uses when run.</p>
    pub fn get_job_run_as_user(&self) -> &::std::option::Option<crate::types::JobRunAsUser> {
        &self.job_run_as_user
    }
    /// <p>The log group name.</p>
    /// This field is required.
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The log group name.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The log group name.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The queue role ARN.</p>
    pub fn queue_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue role ARN.</p>
    pub fn set_queue_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_role_arn = input;
        self
    }
    /// <p>The queue role ARN.</p>
    pub fn get_queue_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_role_arn
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::JobParameter) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>> {
        &self.parameters
    }
    /// <p>The schema version.</p>
    /// This field is required.
    pub fn schema_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The schema version.</p>
    pub fn set_schema_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_version = input;
        self
    }
    /// <p>The schema version.</p>
    pub fn get_schema_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_version
    }
    /// Appends an item to `path_mapping_rules`.
    ///
    /// To override the contents of this collection use [`set_path_mapping_rules`](Self::set_path_mapping_rules).
    ///
    /// <p>The path mapping rules.</p>
    pub fn path_mapping_rules(mut self, input: crate::types::PathMappingRule) -> Self {
        let mut v = self.path_mapping_rules.unwrap_or_default();
        v.push(input);
        self.path_mapping_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The path mapping rules.</p>
    pub fn set_path_mapping_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PathMappingRule>>) -> Self {
        self.path_mapping_rules = input;
        self
    }
    /// <p>The path mapping rules.</p>
    pub fn get_path_mapping_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PathMappingRule>> {
        &self.path_mapping_rules
    }
    /// Consumes the builder and constructs a [`JobDetailsEntity`](crate::types::JobDetailsEntity).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_id`](crate::types::builders::JobDetailsEntityBuilder::job_id)
    /// - [`log_group_name`](crate::types::builders::JobDetailsEntityBuilder::log_group_name)
    /// - [`schema_version`](crate::types::builders::JobDetailsEntityBuilder::schema_version)
    pub fn build(self) -> ::std::result::Result<crate::types::JobDetailsEntity, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::JobDetailsEntity {
            job_id: self.job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_id",
                    "job_id was not specified but it is required when building JobDetailsEntity",
                )
            })?,
            job_attachment_settings: self.job_attachment_settings,
            job_run_as_user: self.job_run_as_user,
            log_group_name: self.log_group_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "log_group_name",
                    "log_group_name was not specified but it is required when building JobDetailsEntity",
                )
            })?,
            queue_role_arn: self.queue_role_arn,
            parameters: self.parameters,
            schema_version: self.schema_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "schema_version",
                    "schema_version was not specified but it is required when building JobDetailsEntity",
                )
            })?,
            path_mapping_rules: self.path_mapping_rules,
        })
    }
}
impl ::std::fmt::Debug for JobDetailsEntityBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("JobDetailsEntityBuilder");
        formatter.field("job_id", &self.job_id);
        formatter.field("job_attachment_settings", &self.job_attachment_settings);
        formatter.field("job_run_as_user", &self.job_run_as_user);
        formatter.field("log_group_name", &self.log_group_name);
        formatter.field("queue_role_arn", &self.queue_role_arn);
        formatter.field("parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("schema_version", &self.schema_version);
        formatter.field("path_mapping_rules", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
