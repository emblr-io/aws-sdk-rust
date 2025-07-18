// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container element for the job configuration and status information returned by a <code>Describe Job</code> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobDescriptor {
    /// <p>The ID for the specified job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether confirmation is required before Amazon S3 begins running the specified job. Confirmation is required only for jobs created through the Amazon S3 console.</p>
    pub confirmation_required: ::std::option::Option<bool>,
    /// <p>The description for this job, if one was provided in this job's <code>Create Job</code> request.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for this job.</p>
    pub job_arn: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the specified job.</p>
    pub status: ::std::option::Option<crate::types::JobStatus>,
    /// <p>The configuration information for the specified job's manifest object.</p>
    pub manifest: ::std::option::Option<crate::types::JobManifest>,
    /// <p>The operation that the specified job is configured to run on the objects listed in the manifest.</p>
    pub operation: ::std::option::Option<crate::types::JobOperation>,
    /// <p>The priority of the specified job.</p>
    pub priority: i32,
    /// <p>Describes the total number of tasks that the specified job has run, the number of tasks that succeeded, and the number of tasks that failed.</p>
    pub progress_summary: ::std::option::Option<crate::types::JobProgressSummary>,
    /// <p>The reason for updating the job.</p>
    pub status_update_reason: ::std::option::Option<::std::string::String>,
    /// <p>If the specified job failed, this field contains information describing the failure.</p>
    pub failure_reasons: ::std::option::Option<::std::vec::Vec<crate::types::JobFailure>>,
    /// <p>Contains the configuration information for the job-completion report if you requested one in the <code>Create Job</code> request.</p>
    pub report: ::std::option::Option<crate::types::JobReport>,
    /// <p>A timestamp indicating when this job was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp indicating when this job terminated. A job's termination date is the date and time when it succeeded, failed, or was canceled.</p>
    pub termination_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) for the Identity and Access Management (IAM) role assigned to run the tasks for this job.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when this job was suspended, if it has been suspended.</p>
    pub suspended_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The reason why the specified job was suspended. A job is only suspended if you create it through the Amazon S3 console. When you create the job, it enters the <code>Suspended</code> state to await confirmation before running. After you confirm the job, it automatically exits the <code>Suspended</code> state.</p>
    pub suspended_cause: ::std::option::Option<::std::string::String>,
    /// <p>The manifest generator that was used to generate a job manifest for this job.</p>
    pub manifest_generator: ::std::option::Option<crate::types::JobManifestGenerator>,
    /// <p>The attribute of the JobDescriptor containing details about the job's generated manifest.</p>
    pub generated_manifest_descriptor: ::std::option::Option<crate::types::S3GeneratedManifestDescriptor>,
}
impl JobDescriptor {
    /// <p>The ID for the specified job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>Indicates whether confirmation is required before Amazon S3 begins running the specified job. Confirmation is required only for jobs created through the Amazon S3 console.</p>
    pub fn confirmation_required(&self) -> ::std::option::Option<bool> {
        self.confirmation_required
    }
    /// <p>The description for this job, if one was provided in this job's <code>Create Job</code> request.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for this job.</p>
    pub fn job_arn(&self) -> ::std::option::Option<&str> {
        self.job_arn.as_deref()
    }
    /// <p>The current status of the specified job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::JobStatus> {
        self.status.as_ref()
    }
    /// <p>The configuration information for the specified job's manifest object.</p>
    pub fn manifest(&self) -> ::std::option::Option<&crate::types::JobManifest> {
        self.manifest.as_ref()
    }
    /// <p>The operation that the specified job is configured to run on the objects listed in the manifest.</p>
    pub fn operation(&self) -> ::std::option::Option<&crate::types::JobOperation> {
        self.operation.as_ref()
    }
    /// <p>The priority of the specified job.</p>
    pub fn priority(&self) -> i32 {
        self.priority
    }
    /// <p>Describes the total number of tasks that the specified job has run, the number of tasks that succeeded, and the number of tasks that failed.</p>
    pub fn progress_summary(&self) -> ::std::option::Option<&crate::types::JobProgressSummary> {
        self.progress_summary.as_ref()
    }
    /// <p>The reason for updating the job.</p>
    pub fn status_update_reason(&self) -> ::std::option::Option<&str> {
        self.status_update_reason.as_deref()
    }
    /// <p>If the specified job failed, this field contains information describing the failure.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failure_reasons.is_none()`.
    pub fn failure_reasons(&self) -> &[crate::types::JobFailure] {
        self.failure_reasons.as_deref().unwrap_or_default()
    }
    /// <p>Contains the configuration information for the job-completion report if you requested one in the <code>Create Job</code> request.</p>
    pub fn report(&self) -> ::std::option::Option<&crate::types::JobReport> {
        self.report.as_ref()
    }
    /// <p>A timestamp indicating when this job was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>A timestamp indicating when this job terminated. A job's termination date is the date and time when it succeeded, failed, or was canceled.</p>
    pub fn termination_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.termination_date.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the Identity and Access Management (IAM) role assigned to run the tasks for this job.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The timestamp when this job was suspended, if it has been suspended.</p>
    pub fn suspended_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.suspended_date.as_ref()
    }
    /// <p>The reason why the specified job was suspended. A job is only suspended if you create it through the Amazon S3 console. When you create the job, it enters the <code>Suspended</code> state to await confirmation before running. After you confirm the job, it automatically exits the <code>Suspended</code> state.</p>
    pub fn suspended_cause(&self) -> ::std::option::Option<&str> {
        self.suspended_cause.as_deref()
    }
    /// <p>The manifest generator that was used to generate a job manifest for this job.</p>
    pub fn manifest_generator(&self) -> ::std::option::Option<&crate::types::JobManifestGenerator> {
        self.manifest_generator.as_ref()
    }
    /// <p>The attribute of the JobDescriptor containing details about the job's generated manifest.</p>
    pub fn generated_manifest_descriptor(&self) -> ::std::option::Option<&crate::types::S3GeneratedManifestDescriptor> {
        self.generated_manifest_descriptor.as_ref()
    }
}
impl JobDescriptor {
    /// Creates a new builder-style object to manufacture [`JobDescriptor`](crate::types::JobDescriptor).
    pub fn builder() -> crate::types::builders::JobDescriptorBuilder {
        crate::types::builders::JobDescriptorBuilder::default()
    }
}

/// A builder for [`JobDescriptor`](crate::types::JobDescriptor).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobDescriptorBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) confirmation_required: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::JobStatus>,
    pub(crate) manifest: ::std::option::Option<crate::types::JobManifest>,
    pub(crate) operation: ::std::option::Option<crate::types::JobOperation>,
    pub(crate) priority: ::std::option::Option<i32>,
    pub(crate) progress_summary: ::std::option::Option<crate::types::JobProgressSummary>,
    pub(crate) status_update_reason: ::std::option::Option<::std::string::String>,
    pub(crate) failure_reasons: ::std::option::Option<::std::vec::Vec<crate::types::JobFailure>>,
    pub(crate) report: ::std::option::Option<crate::types::JobReport>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) termination_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) suspended_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) suspended_cause: ::std::option::Option<::std::string::String>,
    pub(crate) manifest_generator: ::std::option::Option<crate::types::JobManifestGenerator>,
    pub(crate) generated_manifest_descriptor: ::std::option::Option<crate::types::S3GeneratedManifestDescriptor>,
}
impl JobDescriptorBuilder {
    /// <p>The ID for the specified job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the specified job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID for the specified job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>Indicates whether confirmation is required before Amazon S3 begins running the specified job. Confirmation is required only for jobs created through the Amazon S3 console.</p>
    pub fn confirmation_required(mut self, input: bool) -> Self {
        self.confirmation_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether confirmation is required before Amazon S3 begins running the specified job. Confirmation is required only for jobs created through the Amazon S3 console.</p>
    pub fn set_confirmation_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.confirmation_required = input;
        self
    }
    /// <p>Indicates whether confirmation is required before Amazon S3 begins running the specified job. Confirmation is required only for jobs created through the Amazon S3 console.</p>
    pub fn get_confirmation_required(&self) -> &::std::option::Option<bool> {
        &self.confirmation_required
    }
    /// <p>The description for this job, if one was provided in this job's <code>Create Job</code> request.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for this job, if one was provided in this job's <code>Create Job</code> request.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for this job, if one was provided in this job's <code>Create Job</code> request.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon Resource Name (ARN) for this job.</p>
    pub fn job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for this job.</p>
    pub fn set_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for this job.</p>
    pub fn get_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_arn
    }
    /// <p>The current status of the specified job.</p>
    pub fn status(mut self, input: crate::types::JobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the specified job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::JobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the specified job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::JobStatus> {
        &self.status
    }
    /// <p>The configuration information for the specified job's manifest object.</p>
    pub fn manifest(mut self, input: crate::types::JobManifest) -> Self {
        self.manifest = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information for the specified job's manifest object.</p>
    pub fn set_manifest(mut self, input: ::std::option::Option<crate::types::JobManifest>) -> Self {
        self.manifest = input;
        self
    }
    /// <p>The configuration information for the specified job's manifest object.</p>
    pub fn get_manifest(&self) -> &::std::option::Option<crate::types::JobManifest> {
        &self.manifest
    }
    /// <p>The operation that the specified job is configured to run on the objects listed in the manifest.</p>
    pub fn operation(mut self, input: crate::types::JobOperation) -> Self {
        self.operation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation that the specified job is configured to run on the objects listed in the manifest.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<crate::types::JobOperation>) -> Self {
        self.operation = input;
        self
    }
    /// <p>The operation that the specified job is configured to run on the objects listed in the manifest.</p>
    pub fn get_operation(&self) -> &::std::option::Option<crate::types::JobOperation> {
        &self.operation
    }
    /// <p>The priority of the specified job.</p>
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority of the specified job.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The priority of the specified job.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// <p>Describes the total number of tasks that the specified job has run, the number of tasks that succeeded, and the number of tasks that failed.</p>
    pub fn progress_summary(mut self, input: crate::types::JobProgressSummary) -> Self {
        self.progress_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the total number of tasks that the specified job has run, the number of tasks that succeeded, and the number of tasks that failed.</p>
    pub fn set_progress_summary(mut self, input: ::std::option::Option<crate::types::JobProgressSummary>) -> Self {
        self.progress_summary = input;
        self
    }
    /// <p>Describes the total number of tasks that the specified job has run, the number of tasks that succeeded, and the number of tasks that failed.</p>
    pub fn get_progress_summary(&self) -> &::std::option::Option<crate::types::JobProgressSummary> {
        &self.progress_summary
    }
    /// <p>The reason for updating the job.</p>
    pub fn status_update_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_update_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason for updating the job.</p>
    pub fn set_status_update_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_update_reason = input;
        self
    }
    /// <p>The reason for updating the job.</p>
    pub fn get_status_update_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_update_reason
    }
    /// Appends an item to `failure_reasons`.
    ///
    /// To override the contents of this collection use [`set_failure_reasons`](Self::set_failure_reasons).
    ///
    /// <p>If the specified job failed, this field contains information describing the failure.</p>
    pub fn failure_reasons(mut self, input: crate::types::JobFailure) -> Self {
        let mut v = self.failure_reasons.unwrap_or_default();
        v.push(input);
        self.failure_reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>If the specified job failed, this field contains information describing the failure.</p>
    pub fn set_failure_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::JobFailure>>) -> Self {
        self.failure_reasons = input;
        self
    }
    /// <p>If the specified job failed, this field contains information describing the failure.</p>
    pub fn get_failure_reasons(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::JobFailure>> {
        &self.failure_reasons
    }
    /// <p>Contains the configuration information for the job-completion report if you requested one in the <code>Create Job</code> request.</p>
    pub fn report(mut self, input: crate::types::JobReport) -> Self {
        self.report = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the configuration information for the job-completion report if you requested one in the <code>Create Job</code> request.</p>
    pub fn set_report(mut self, input: ::std::option::Option<crate::types::JobReport>) -> Self {
        self.report = input;
        self
    }
    /// <p>Contains the configuration information for the job-completion report if you requested one in the <code>Create Job</code> request.</p>
    pub fn get_report(&self) -> &::std::option::Option<crate::types::JobReport> {
        &self.report
    }
    /// <p>A timestamp indicating when this job was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp indicating when this job was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>A timestamp indicating when this job was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>A timestamp indicating when this job terminated. A job's termination date is the date and time when it succeeded, failed, or was canceled.</p>
    pub fn termination_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.termination_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp indicating when this job terminated. A job's termination date is the date and time when it succeeded, failed, or was canceled.</p>
    pub fn set_termination_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.termination_date = input;
        self
    }
    /// <p>A timestamp indicating when this job terminated. A job's termination date is the date and time when it succeeded, failed, or was canceled.</p>
    pub fn get_termination_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.termination_date
    }
    /// <p>The Amazon Resource Name (ARN) for the Identity and Access Management (IAM) role assigned to run the tasks for this job.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the Identity and Access Management (IAM) role assigned to run the tasks for this job.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the Identity and Access Management (IAM) role assigned to run the tasks for this job.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The timestamp when this job was suspended, if it has been suspended.</p>
    pub fn suspended_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.suspended_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when this job was suspended, if it has been suspended.</p>
    pub fn set_suspended_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.suspended_date = input;
        self
    }
    /// <p>The timestamp when this job was suspended, if it has been suspended.</p>
    pub fn get_suspended_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.suspended_date
    }
    /// <p>The reason why the specified job was suspended. A job is only suspended if you create it through the Amazon S3 console. When you create the job, it enters the <code>Suspended</code> state to await confirmation before running. After you confirm the job, it automatically exits the <code>Suspended</code> state.</p>
    pub fn suspended_cause(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suspended_cause = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason why the specified job was suspended. A job is only suspended if you create it through the Amazon S3 console. When you create the job, it enters the <code>Suspended</code> state to await confirmation before running. After you confirm the job, it automatically exits the <code>Suspended</code> state.</p>
    pub fn set_suspended_cause(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suspended_cause = input;
        self
    }
    /// <p>The reason why the specified job was suspended. A job is only suspended if you create it through the Amazon S3 console. When you create the job, it enters the <code>Suspended</code> state to await confirmation before running. After you confirm the job, it automatically exits the <code>Suspended</code> state.</p>
    pub fn get_suspended_cause(&self) -> &::std::option::Option<::std::string::String> {
        &self.suspended_cause
    }
    /// <p>The manifest generator that was used to generate a job manifest for this job.</p>
    pub fn manifest_generator(mut self, input: crate::types::JobManifestGenerator) -> Self {
        self.manifest_generator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The manifest generator that was used to generate a job manifest for this job.</p>
    pub fn set_manifest_generator(mut self, input: ::std::option::Option<crate::types::JobManifestGenerator>) -> Self {
        self.manifest_generator = input;
        self
    }
    /// <p>The manifest generator that was used to generate a job manifest for this job.</p>
    pub fn get_manifest_generator(&self) -> &::std::option::Option<crate::types::JobManifestGenerator> {
        &self.manifest_generator
    }
    /// <p>The attribute of the JobDescriptor containing details about the job's generated manifest.</p>
    pub fn generated_manifest_descriptor(mut self, input: crate::types::S3GeneratedManifestDescriptor) -> Self {
        self.generated_manifest_descriptor = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attribute of the JobDescriptor containing details about the job's generated manifest.</p>
    pub fn set_generated_manifest_descriptor(mut self, input: ::std::option::Option<crate::types::S3GeneratedManifestDescriptor>) -> Self {
        self.generated_manifest_descriptor = input;
        self
    }
    /// <p>The attribute of the JobDescriptor containing details about the job's generated manifest.</p>
    pub fn get_generated_manifest_descriptor(&self) -> &::std::option::Option<crate::types::S3GeneratedManifestDescriptor> {
        &self.generated_manifest_descriptor
    }
    /// Consumes the builder and constructs a [`JobDescriptor`](crate::types::JobDescriptor).
    pub fn build(self) -> crate::types::JobDescriptor {
        crate::types::JobDescriptor {
            job_id: self.job_id,
            confirmation_required: self.confirmation_required,
            description: self.description,
            job_arn: self.job_arn,
            status: self.status,
            manifest: self.manifest,
            operation: self.operation,
            priority: self.priority.unwrap_or_default(),
            progress_summary: self.progress_summary,
            status_update_reason: self.status_update_reason,
            failure_reasons: self.failure_reasons,
            report: self.report,
            creation_time: self.creation_time,
            termination_date: self.termination_date,
            role_arn: self.role_arn,
            suspended_date: self.suspended_date,
            suspended_cause: self.suspended_cause,
            manifest_generator: self.manifest_generator,
            generated_manifest_descriptor: self.generated_manifest_descriptor,
        }
    }
}
