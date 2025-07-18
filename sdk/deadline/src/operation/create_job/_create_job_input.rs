// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateJobInput {
    /// <p>The farm ID of the farm to connect to the job.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the queue that the job is submitted to.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The job template to use for this job.</p>
    pub template: ::std::option::Option<::std::string::String>,
    /// <p>The file type for the job template.</p>
    pub template_type: ::std::option::Option<crate::types::JobTemplateType>,
    /// <p>The priority of the job. The highest priority (first scheduled) is 100. When two jobs have the same priority, the oldest job is scheduled first.</p>
    pub priority: ::std::option::Option<i32>,
    /// <p>The parameters for the job.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    /// <p>The attachments for the job. Attach files required for the job to run to a render job.</p>
    pub attachments: ::std::option::Option<crate::types::Attachments>,
    /// <p>The storage profile ID for the storage profile to connect to the job.</p>
    pub storage_profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The initial job status when it is created. Jobs that are created with a <code>SUSPENDED</code> status will not run until manually requeued.</p>
    pub target_task_run_status: ::std::option::Option<crate::types::CreateJobTargetTaskRunStatus>,
    /// <p>The number of task failures before the job stops running and is marked as <code>FAILED</code>.</p>
    pub max_failed_tasks_count: ::std::option::Option<i32>,
    /// <p>The maximum number of retries for each task.</p>
    pub max_retries_per_task: ::std::option::Option<i32>,
    /// <p>The maximum number of worker hosts that can concurrently process a job. When the <code>maxWorkerCount</code> is reached, no more workers will be assigned to process the job, even if the fleets assigned to the job's queue has available workers.</p>
    /// <p>You can't set the <code>maxWorkerCount</code> to 0. If you set it to -1, there is no maximum number of workers.</p>
    /// <p>If you don't specify the <code>maxWorkerCount</code>, Deadline Cloud won't throttle the number of workers used to process the job.</p>
    pub max_worker_count: ::std::option::Option<i32>,
    /// <p>The job ID for the source job.</p>
    pub source_job_id: ::std::option::Option<::std::string::String>,
}
impl CreateJobInput {
    /// <p>The farm ID of the farm to connect to the job.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The ID of the queue that the job is submitted to.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The job template to use for this job.</p>
    pub fn template(&self) -> ::std::option::Option<&str> {
        self.template.as_deref()
    }
    /// <p>The file type for the job template.</p>
    pub fn template_type(&self) -> ::std::option::Option<&crate::types::JobTemplateType> {
        self.template_type.as_ref()
    }
    /// <p>The priority of the job. The highest priority (first scheduled) is 100. When two jobs have the same priority, the oldest job is scheduled first.</p>
    pub fn priority(&self) -> ::std::option::Option<i32> {
        self.priority
    }
    /// <p>The parameters for the job.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::JobParameter>> {
        self.parameters.as_ref()
    }
    /// <p>The attachments for the job. Attach files required for the job to run to a render job.</p>
    pub fn attachments(&self) -> ::std::option::Option<&crate::types::Attachments> {
        self.attachments.as_ref()
    }
    /// <p>The storage profile ID for the storage profile to connect to the job.</p>
    pub fn storage_profile_id(&self) -> ::std::option::Option<&str> {
        self.storage_profile_id.as_deref()
    }
    /// <p>The initial job status when it is created. Jobs that are created with a <code>SUSPENDED</code> status will not run until manually requeued.</p>
    pub fn target_task_run_status(&self) -> ::std::option::Option<&crate::types::CreateJobTargetTaskRunStatus> {
        self.target_task_run_status.as_ref()
    }
    /// <p>The number of task failures before the job stops running and is marked as <code>FAILED</code>.</p>
    pub fn max_failed_tasks_count(&self) -> ::std::option::Option<i32> {
        self.max_failed_tasks_count
    }
    /// <p>The maximum number of retries for each task.</p>
    pub fn max_retries_per_task(&self) -> ::std::option::Option<i32> {
        self.max_retries_per_task
    }
    /// <p>The maximum number of worker hosts that can concurrently process a job. When the <code>maxWorkerCount</code> is reached, no more workers will be assigned to process the job, even if the fleets assigned to the job's queue has available workers.</p>
    /// <p>You can't set the <code>maxWorkerCount</code> to 0. If you set it to -1, there is no maximum number of workers.</p>
    /// <p>If you don't specify the <code>maxWorkerCount</code>, Deadline Cloud won't throttle the number of workers used to process the job.</p>
    pub fn max_worker_count(&self) -> ::std::option::Option<i32> {
        self.max_worker_count
    }
    /// <p>The job ID for the source job.</p>
    pub fn source_job_id(&self) -> ::std::option::Option<&str> {
        self.source_job_id.as_deref()
    }
}
impl ::std::fmt::Debug for CreateJobInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateJobInput");
        formatter.field("farm_id", &self.farm_id);
        formatter.field("queue_id", &self.queue_id);
        formatter.field("client_token", &self.client_token);
        formatter.field("template", &"*** Sensitive Data Redacted ***");
        formatter.field("template_type", &self.template_type);
        formatter.field("priority", &self.priority);
        formatter.field("parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("attachments", &self.attachments);
        formatter.field("storage_profile_id", &self.storage_profile_id);
        formatter.field("target_task_run_status", &self.target_task_run_status);
        formatter.field("max_failed_tasks_count", &self.max_failed_tasks_count);
        formatter.field("max_retries_per_task", &self.max_retries_per_task);
        formatter.field("max_worker_count", &self.max_worker_count);
        formatter.field("source_job_id", &self.source_job_id);
        formatter.finish()
    }
}
impl CreateJobInput {
    /// Creates a new builder-style object to manufacture [`CreateJobInput`](crate::operation::create_job::CreateJobInput).
    pub fn builder() -> crate::operation::create_job::builders::CreateJobInputBuilder {
        crate::operation::create_job::builders::CreateJobInputBuilder::default()
    }
}

/// A builder for [`CreateJobInput`](crate::operation::create_job::CreateJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateJobInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) template: ::std::option::Option<::std::string::String>,
    pub(crate) template_type: ::std::option::Option<crate::types::JobTemplateType>,
    pub(crate) priority: ::std::option::Option<i32>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    pub(crate) attachments: ::std::option::Option<crate::types::Attachments>,
    pub(crate) storage_profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_task_run_status: ::std::option::Option<crate::types::CreateJobTargetTaskRunStatus>,
    pub(crate) max_failed_tasks_count: ::std::option::Option<i32>,
    pub(crate) max_retries_per_task: ::std::option::Option<i32>,
    pub(crate) max_worker_count: ::std::option::Option<i32>,
    pub(crate) source_job_id: ::std::option::Option<::std::string::String>,
}
impl CreateJobInputBuilder {
    /// <p>The farm ID of the farm to connect to the job.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID of the farm to connect to the job.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID of the farm to connect to the job.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The ID of the queue that the job is submitted to.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the queue that the job is submitted to.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The ID of the queue that the job is submitted to.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The job template to use for this job.</p>
    pub fn template(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job template to use for this job.</p>
    pub fn set_template(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template = input;
        self
    }
    /// <p>The job template to use for this job.</p>
    pub fn get_template(&self) -> &::std::option::Option<::std::string::String> {
        &self.template
    }
    /// <p>The file type for the job template.</p>
    pub fn template_type(mut self, input: crate::types::JobTemplateType) -> Self {
        self.template_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file type for the job template.</p>
    pub fn set_template_type(mut self, input: ::std::option::Option<crate::types::JobTemplateType>) -> Self {
        self.template_type = input;
        self
    }
    /// <p>The file type for the job template.</p>
    pub fn get_template_type(&self) -> &::std::option::Option<crate::types::JobTemplateType> {
        &self.template_type
    }
    /// <p>The priority of the job. The highest priority (first scheduled) is 100. When two jobs have the same priority, the oldest job is scheduled first.</p>
    /// This field is required.
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority of the job. The highest priority (first scheduled) is 100. When two jobs have the same priority, the oldest job is scheduled first.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The priority of the job. The highest priority (first scheduled) is 100. When two jobs have the same priority, the oldest job is scheduled first.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters for the job.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::JobParameter) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters for the job.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for the job.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::JobParameter>> {
        &self.parameters
    }
    /// <p>The attachments for the job. Attach files required for the job to run to a render job.</p>
    pub fn attachments(mut self, input: crate::types::Attachments) -> Self {
        self.attachments = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attachments for the job. Attach files required for the job to run to a render job.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<crate::types::Attachments>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>The attachments for the job. Attach files required for the job to run to a render job.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<crate::types::Attachments> {
        &self.attachments
    }
    /// <p>The storage profile ID for the storage profile to connect to the job.</p>
    pub fn storage_profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.storage_profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The storage profile ID for the storage profile to connect to the job.</p>
    pub fn set_storage_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.storage_profile_id = input;
        self
    }
    /// <p>The storage profile ID for the storage profile to connect to the job.</p>
    pub fn get_storage_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.storage_profile_id
    }
    /// <p>The initial job status when it is created. Jobs that are created with a <code>SUSPENDED</code> status will not run until manually requeued.</p>
    pub fn target_task_run_status(mut self, input: crate::types::CreateJobTargetTaskRunStatus) -> Self {
        self.target_task_run_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The initial job status when it is created. Jobs that are created with a <code>SUSPENDED</code> status will not run until manually requeued.</p>
    pub fn set_target_task_run_status(mut self, input: ::std::option::Option<crate::types::CreateJobTargetTaskRunStatus>) -> Self {
        self.target_task_run_status = input;
        self
    }
    /// <p>The initial job status when it is created. Jobs that are created with a <code>SUSPENDED</code> status will not run until manually requeued.</p>
    pub fn get_target_task_run_status(&self) -> &::std::option::Option<crate::types::CreateJobTargetTaskRunStatus> {
        &self.target_task_run_status
    }
    /// <p>The number of task failures before the job stops running and is marked as <code>FAILED</code>.</p>
    pub fn max_failed_tasks_count(mut self, input: i32) -> Self {
        self.max_failed_tasks_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of task failures before the job stops running and is marked as <code>FAILED</code>.</p>
    pub fn set_max_failed_tasks_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_failed_tasks_count = input;
        self
    }
    /// <p>The number of task failures before the job stops running and is marked as <code>FAILED</code>.</p>
    pub fn get_max_failed_tasks_count(&self) -> &::std::option::Option<i32> {
        &self.max_failed_tasks_count
    }
    /// <p>The maximum number of retries for each task.</p>
    pub fn max_retries_per_task(mut self, input: i32) -> Self {
        self.max_retries_per_task = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of retries for each task.</p>
    pub fn set_max_retries_per_task(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_retries_per_task = input;
        self
    }
    /// <p>The maximum number of retries for each task.</p>
    pub fn get_max_retries_per_task(&self) -> &::std::option::Option<i32> {
        &self.max_retries_per_task
    }
    /// <p>The maximum number of worker hosts that can concurrently process a job. When the <code>maxWorkerCount</code> is reached, no more workers will be assigned to process the job, even if the fleets assigned to the job's queue has available workers.</p>
    /// <p>You can't set the <code>maxWorkerCount</code> to 0. If you set it to -1, there is no maximum number of workers.</p>
    /// <p>If you don't specify the <code>maxWorkerCount</code>, Deadline Cloud won't throttle the number of workers used to process the job.</p>
    pub fn max_worker_count(mut self, input: i32) -> Self {
        self.max_worker_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of worker hosts that can concurrently process a job. When the <code>maxWorkerCount</code> is reached, no more workers will be assigned to process the job, even if the fleets assigned to the job's queue has available workers.</p>
    /// <p>You can't set the <code>maxWorkerCount</code> to 0. If you set it to -1, there is no maximum number of workers.</p>
    /// <p>If you don't specify the <code>maxWorkerCount</code>, Deadline Cloud won't throttle the number of workers used to process the job.</p>
    pub fn set_max_worker_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_worker_count = input;
        self
    }
    /// <p>The maximum number of worker hosts that can concurrently process a job. When the <code>maxWorkerCount</code> is reached, no more workers will be assigned to process the job, even if the fleets assigned to the job's queue has available workers.</p>
    /// <p>You can't set the <code>maxWorkerCount</code> to 0. If you set it to -1, there is no maximum number of workers.</p>
    /// <p>If you don't specify the <code>maxWorkerCount</code>, Deadline Cloud won't throttle the number of workers used to process the job.</p>
    pub fn get_max_worker_count(&self) -> &::std::option::Option<i32> {
        &self.max_worker_count
    }
    /// <p>The job ID for the source job.</p>
    pub fn source_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job ID for the source job.</p>
    pub fn set_source_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_job_id = input;
        self
    }
    /// <p>The job ID for the source job.</p>
    pub fn get_source_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_job_id
    }
    /// Consumes the builder and constructs a [`CreateJobInput`](crate::operation::create_job::CreateJobInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_job::CreateJobInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_job::CreateJobInput {
            farm_id: self.farm_id,
            queue_id: self.queue_id,
            client_token: self.client_token,
            template: self.template,
            template_type: self.template_type,
            priority: self.priority,
            parameters: self.parameters,
            attachments: self.attachments,
            storage_profile_id: self.storage_profile_id,
            target_task_run_status: self.target_task_run_status,
            max_failed_tasks_count: self.max_failed_tasks_count,
            max_retries_per_task: self.max_retries_per_task,
            max_worker_count: self.max_worker_count,
            source_job_id: self.source_job_id,
        })
    }
}
impl ::std::fmt::Debug for CreateJobInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateJobInputBuilder");
        formatter.field("farm_id", &self.farm_id);
        formatter.field("queue_id", &self.queue_id);
        formatter.field("client_token", &self.client_token);
        formatter.field("template", &"*** Sensitive Data Redacted ***");
        formatter.field("template_type", &self.template_type);
        formatter.field("priority", &self.priority);
        formatter.field("parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("attachments", &self.attachments);
        formatter.field("storage_profile_id", &self.storage_profile_id);
        formatter.field("target_task_run_status", &self.target_task_run_status);
        formatter.field("max_failed_tasks_count", &self.max_failed_tasks_count);
        formatter.field("max_retries_per_task", &self.max_retries_per_task);
        formatter.field("max_worker_count", &self.max_worker_count);
        formatter.field("source_job_id", &self.source_job_id);
        formatter.finish()
    }
}
