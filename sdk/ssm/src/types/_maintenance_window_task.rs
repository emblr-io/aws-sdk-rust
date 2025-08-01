// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a task defined for a maintenance window.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct MaintenanceWindowTask {
    /// <p>The ID of the maintenance window where the task is registered.</p>
    pub window_id: ::std::option::Option<::std::string::String>,
    /// <p>The task ID.</p>
    pub window_task_id: ::std::option::Option<::std::string::String>,
    /// <p>The resource that the task uses during execution. For <code>RUN_COMMAND</code> and <code>AUTOMATION</code> task types, <code>TaskArn</code> is the Amazon Web Services Systems Manager (SSM document) name or ARN. For <code>LAMBDA</code> tasks, it's the function name or ARN. For <code>STEP_FUNCTIONS</code> tasks, it's the state machine ARN.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of task.</p>
    pub r#type: ::std::option::Option<crate::types::MaintenanceWindowTaskType>,
    /// <p>The targets (either managed nodes or tags). Managed nodes are specified using <code>Key=instanceids,Values=<instanceid1>
    /// ,
    /// <instanceid2></instanceid2>
    /// </instanceid1></code>. Tags are specified using <code>Key=<tag name>
    /// ,Values=
    /// <tag value></tag>
    /// </tag></code>.</p>
    pub targets: ::std::option::Option<::std::vec::Vec<crate::types::Target>>,
    /// <p>The parameters that should be passed to the task when it is run.</p><note>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub task_parameters:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MaintenanceWindowTaskParameterValueExpression>>,
    /// <p>The priority of the task in the maintenance window. The lower the number, the higher the priority. Tasks that have the same priority are scheduled in parallel.</p>
    pub priority: i32,
    /// <p>Information about an S3 bucket to write task-level logs to.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub logging_info: ::std::option::Option<crate::types::LoggingInfo>,
    /// <p>The Amazon Resource Name (ARN) of the IAM service role for Amazon Web Services Systems Manager to assume when running a maintenance window task. If you do not specify a service role ARN, Systems Manager uses a service-linked role in your account. If no appropriate service-linked role for Systems Manager exists in your account, it is created when you run <code>RegisterTaskWithMaintenanceWindow</code>.</p>
    /// <p>However, for an improved security posture, we strongly recommend creating a custom policy and custom service role for running your maintenance window tasks. The policy can be crafted to provide only the permissions needed for your particular maintenance window tasks. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-permissions.html">Setting up Maintenance Windows</a> in the in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub service_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of targets this task can be run for, in parallel.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub max_concurrency: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of errors allowed before this task stops being scheduled.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub max_errors: ::std::option::Option<::std::string::String>,
    /// <p>The task name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the task.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The specification for whether tasks should continue to run after the cutoff time specified in the maintenance windows is reached.</p>
    pub cutoff_behavior: ::std::option::Option<crate::types::MaintenanceWindowTaskCutoffBehavior>,
    /// <p>The details for the CloudWatch alarm applied to your maintenance window task.</p>
    pub alarm_configuration: ::std::option::Option<crate::types::AlarmConfiguration>,
}
impl MaintenanceWindowTask {
    /// <p>The ID of the maintenance window where the task is registered.</p>
    pub fn window_id(&self) -> ::std::option::Option<&str> {
        self.window_id.as_deref()
    }
    /// <p>The task ID.</p>
    pub fn window_task_id(&self) -> ::std::option::Option<&str> {
        self.window_task_id.as_deref()
    }
    /// <p>The resource that the task uses during execution. For <code>RUN_COMMAND</code> and <code>AUTOMATION</code> task types, <code>TaskArn</code> is the Amazon Web Services Systems Manager (SSM document) name or ARN. For <code>LAMBDA</code> tasks, it's the function name or ARN. For <code>STEP_FUNCTIONS</code> tasks, it's the state machine ARN.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
    /// <p>The type of task.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowTaskType> {
        self.r#type.as_ref()
    }
    /// <p>The targets (either managed nodes or tags). Managed nodes are specified using <code>Key=instanceids,Values=<instanceid1>
    /// ,
    /// <instanceid2></instanceid2>
    /// </instanceid1></code>. Tags are specified using <code>Key=<tag name>
    /// ,Values=
    /// <tag value></tag>
    /// </tag></code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.targets.is_none()`.
    pub fn targets(&self) -> &[crate::types::Target] {
        self.targets.as_deref().unwrap_or_default()
    }
    /// <p>The parameters that should be passed to the task when it is run.</p><note>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn task_parameters(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::MaintenanceWindowTaskParameterValueExpression>> {
        self.task_parameters.as_ref()
    }
    /// <p>The priority of the task in the maintenance window. The lower the number, the higher the priority. Tasks that have the same priority are scheduled in parallel.</p>
    pub fn priority(&self) -> i32 {
        self.priority
    }
    /// <p>Information about an S3 bucket to write task-level logs to.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn logging_info(&self) -> ::std::option::Option<&crate::types::LoggingInfo> {
        self.logging_info.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role for Amazon Web Services Systems Manager to assume when running a maintenance window task. If you do not specify a service role ARN, Systems Manager uses a service-linked role in your account. If no appropriate service-linked role for Systems Manager exists in your account, it is created when you run <code>RegisterTaskWithMaintenanceWindow</code>.</p>
    /// <p>However, for an improved security posture, we strongly recommend creating a custom policy and custom service role for running your maintenance window tasks. The policy can be crafted to provide only the permissions needed for your particular maintenance window tasks. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-permissions.html">Setting up Maintenance Windows</a> in the in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn service_role_arn(&self) -> ::std::option::Option<&str> {
        self.service_role_arn.as_deref()
    }
    /// <p>The maximum number of targets this task can be run for, in parallel.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn max_concurrency(&self) -> ::std::option::Option<&str> {
        self.max_concurrency.as_deref()
    }
    /// <p>The maximum number of errors allowed before this task stops being scheduled.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn max_errors(&self) -> ::std::option::Option<&str> {
        self.max_errors.as_deref()
    }
    /// <p>The task name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the task.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The specification for whether tasks should continue to run after the cutoff time specified in the maintenance windows is reached.</p>
    pub fn cutoff_behavior(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowTaskCutoffBehavior> {
        self.cutoff_behavior.as_ref()
    }
    /// <p>The details for the CloudWatch alarm applied to your maintenance window task.</p>
    pub fn alarm_configuration(&self) -> ::std::option::Option<&crate::types::AlarmConfiguration> {
        self.alarm_configuration.as_ref()
    }
}
impl ::std::fmt::Debug for MaintenanceWindowTask {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MaintenanceWindowTask");
        formatter.field("window_id", &self.window_id);
        formatter.field("window_task_id", &self.window_task_id);
        formatter.field("task_arn", &self.task_arn);
        formatter.field("r#type", &self.r#type);
        formatter.field("targets", &self.targets);
        formatter.field("task_parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("priority", &self.priority);
        formatter.field("logging_info", &self.logging_info);
        formatter.field("service_role_arn", &self.service_role_arn);
        formatter.field("max_concurrency", &self.max_concurrency);
        formatter.field("max_errors", &self.max_errors);
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("cutoff_behavior", &self.cutoff_behavior);
        formatter.field("alarm_configuration", &self.alarm_configuration);
        formatter.finish()
    }
}
impl MaintenanceWindowTask {
    /// Creates a new builder-style object to manufacture [`MaintenanceWindowTask`](crate::types::MaintenanceWindowTask).
    pub fn builder() -> crate::types::builders::MaintenanceWindowTaskBuilder {
        crate::types::builders::MaintenanceWindowTaskBuilder::default()
    }
}

/// A builder for [`MaintenanceWindowTask`](crate::types::MaintenanceWindowTask).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct MaintenanceWindowTaskBuilder {
    pub(crate) window_id: ::std::option::Option<::std::string::String>,
    pub(crate) window_task_id: ::std::option::Option<::std::string::String>,
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::MaintenanceWindowTaskType>,
    pub(crate) targets: ::std::option::Option<::std::vec::Vec<crate::types::Target>>,
    pub(crate) task_parameters:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MaintenanceWindowTaskParameterValueExpression>>,
    pub(crate) priority: ::std::option::Option<i32>,
    pub(crate) logging_info: ::std::option::Option<crate::types::LoggingInfo>,
    pub(crate) service_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_concurrency: ::std::option::Option<::std::string::String>,
    pub(crate) max_errors: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) cutoff_behavior: ::std::option::Option<crate::types::MaintenanceWindowTaskCutoffBehavior>,
    pub(crate) alarm_configuration: ::std::option::Option<crate::types::AlarmConfiguration>,
}
impl MaintenanceWindowTaskBuilder {
    /// <p>The ID of the maintenance window where the task is registered.</p>
    pub fn window_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.window_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the maintenance window where the task is registered.</p>
    pub fn set_window_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.window_id = input;
        self
    }
    /// <p>The ID of the maintenance window where the task is registered.</p>
    pub fn get_window_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.window_id
    }
    /// <p>The task ID.</p>
    pub fn window_task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.window_task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The task ID.</p>
    pub fn set_window_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.window_task_id = input;
        self
    }
    /// <p>The task ID.</p>
    pub fn get_window_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.window_task_id
    }
    /// <p>The resource that the task uses during execution. For <code>RUN_COMMAND</code> and <code>AUTOMATION</code> task types, <code>TaskArn</code> is the Amazon Web Services Systems Manager (SSM document) name or ARN. For <code>LAMBDA</code> tasks, it's the function name or ARN. For <code>STEP_FUNCTIONS</code> tasks, it's the state machine ARN.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource that the task uses during execution. For <code>RUN_COMMAND</code> and <code>AUTOMATION</code> task types, <code>TaskArn</code> is the Amazon Web Services Systems Manager (SSM document) name or ARN. For <code>LAMBDA</code> tasks, it's the function name or ARN. For <code>STEP_FUNCTIONS</code> tasks, it's the state machine ARN.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The resource that the task uses during execution. For <code>RUN_COMMAND</code> and <code>AUTOMATION</code> task types, <code>TaskArn</code> is the Amazon Web Services Systems Manager (SSM document) name or ARN. For <code>LAMBDA</code> tasks, it's the function name or ARN. For <code>STEP_FUNCTIONS</code> tasks, it's the state machine ARN.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// <p>The type of task.</p>
    pub fn r#type(mut self, input: crate::types::MaintenanceWindowTaskType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of task.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowTaskType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of task.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::MaintenanceWindowTaskType> {
        &self.r#type
    }
    /// Appends an item to `targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The targets (either managed nodes or tags). Managed nodes are specified using <code>Key=instanceids,Values=<instanceid1>
    /// ,
    /// <instanceid2></instanceid2>
    /// </instanceid1></code>. Tags are specified using <code>Key=<tag name>
    /// ,Values=
    /// <tag value></tag>
    /// </tag></code>.</p>
    pub fn targets(mut self, input: crate::types::Target) -> Self {
        let mut v = self.targets.unwrap_or_default();
        v.push(input);
        self.targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The targets (either managed nodes or tags). Managed nodes are specified using <code>Key=instanceids,Values=<instanceid1>
    /// ,
    /// <instanceid2></instanceid2>
    /// </instanceid1></code>. Tags are specified using <code>Key=<tag name>
    /// ,Values=
    /// <tag value></tag>
    /// </tag></code>.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Target>>) -> Self {
        self.targets = input;
        self
    }
    /// <p>The targets (either managed nodes or tags). Managed nodes are specified using <code>Key=instanceids,Values=<instanceid1>
    /// ,
    /// <instanceid2></instanceid2>
    /// </instanceid1></code>. Tags are specified using <code>Key=<tag name>
    /// ,Values=
    /// <tag value></tag>
    /// </tag></code>.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Target>> {
        &self.targets
    }
    /// Adds a key-value pair to `task_parameters`.
    ///
    /// To override the contents of this collection use [`set_task_parameters`](Self::set_task_parameters).
    ///
    /// <p>The parameters that should be passed to the task when it is run.</p><note>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn task_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: crate::types::MaintenanceWindowTaskParameterValueExpression,
    ) -> Self {
        let mut hash_map = self.task_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.task_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters that should be passed to the task when it is run.</p><note>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn set_task_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MaintenanceWindowTaskParameterValueExpression>>,
    ) -> Self {
        self.task_parameters = input;
        self
    }
    /// <p>The parameters that should be passed to the task when it is run.</p><note>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn get_task_parameters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MaintenanceWindowTaskParameterValueExpression>> {
        &self.task_parameters
    }
    /// <p>The priority of the task in the maintenance window. The lower the number, the higher the priority. Tasks that have the same priority are scheduled in parallel.</p>
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority of the task in the maintenance window. The lower the number, the higher the priority. Tasks that have the same priority are scheduled in parallel.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The priority of the task in the maintenance window. The lower the number, the higher the priority. Tasks that have the same priority are scheduled in parallel.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// <p>Information about an S3 bucket to write task-level logs to.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn logging_info(mut self, input: crate::types::LoggingInfo) -> Self {
        self.logging_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an S3 bucket to write task-level logs to.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn set_logging_info(mut self, input: ::std::option::Option<crate::types::LoggingInfo>) -> Self {
        self.logging_info = input;
        self
    }
    /// <p>Information about an S3 bucket to write task-level logs to.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// </note>
    pub fn get_logging_info(&self) -> &::std::option::Option<crate::types::LoggingInfo> {
        &self.logging_info
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role for Amazon Web Services Systems Manager to assume when running a maintenance window task. If you do not specify a service role ARN, Systems Manager uses a service-linked role in your account. If no appropriate service-linked role for Systems Manager exists in your account, it is created when you run <code>RegisterTaskWithMaintenanceWindow</code>.</p>
    /// <p>However, for an improved security posture, we strongly recommend creating a custom policy and custom service role for running your maintenance window tasks. The policy can be crafted to provide only the permissions needed for your particular maintenance window tasks. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-permissions.html">Setting up Maintenance Windows</a> in the in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn service_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role for Amazon Web Services Systems Manager to assume when running a maintenance window task. If you do not specify a service role ARN, Systems Manager uses a service-linked role in your account. If no appropriate service-linked role for Systems Manager exists in your account, it is created when you run <code>RegisterTaskWithMaintenanceWindow</code>.</p>
    /// <p>However, for an improved security posture, we strongly recommend creating a custom policy and custom service role for running your maintenance window tasks. The policy can be crafted to provide only the permissions needed for your particular maintenance window tasks. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-permissions.html">Setting up Maintenance Windows</a> in the in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_service_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role for Amazon Web Services Systems Manager to assume when running a maintenance window task. If you do not specify a service role ARN, Systems Manager uses a service-linked role in your account. If no appropriate service-linked role for Systems Manager exists in your account, it is created when you run <code>RegisterTaskWithMaintenanceWindow</code>.</p>
    /// <p>However, for an improved security posture, we strongly recommend creating a custom policy and custom service role for running your maintenance window tasks. The policy can be crafted to provide only the permissions needed for your particular maintenance window tasks. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-permissions.html">Setting up Maintenance Windows</a> in the in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_service_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_role_arn
    }
    /// <p>The maximum number of targets this task can be run for, in parallel.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn max_concurrency(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_concurrency = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum number of targets this task can be run for, in parallel.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn set_max_concurrency(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_concurrency = input;
        self
    }
    /// <p>The maximum number of targets this task can be run for, in parallel.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn get_max_concurrency(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_concurrency
    }
    /// <p>The maximum number of errors allowed before this task stops being scheduled.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn max_errors(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_errors = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum number of errors allowed before this task stops being scheduled.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn set_max_errors(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_errors = input;
        self
    }
    /// <p>The maximum number of errors allowed before this task stops being scheduled.</p><note>
    /// <p>Although this element is listed as "Required: No", a value can be omitted only when you are registering or updating a <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-targetless-tasks.html">targetless task</a> You must provide a value in all other cases.</p>
    /// <p>For maintenance window tasks without a target specified, you can't supply a value for this option. Instead, the system inserts a placeholder value of <code>1</code>. This value doesn't affect the running of your task.</p>
    /// </note>
    pub fn get_max_errors(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_errors
    }
    /// <p>The task name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The task name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The task name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the task.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the task.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the task.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The specification for whether tasks should continue to run after the cutoff time specified in the maintenance windows is reached.</p>
    pub fn cutoff_behavior(mut self, input: crate::types::MaintenanceWindowTaskCutoffBehavior) -> Self {
        self.cutoff_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specification for whether tasks should continue to run after the cutoff time specified in the maintenance windows is reached.</p>
    pub fn set_cutoff_behavior(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowTaskCutoffBehavior>) -> Self {
        self.cutoff_behavior = input;
        self
    }
    /// <p>The specification for whether tasks should continue to run after the cutoff time specified in the maintenance windows is reached.</p>
    pub fn get_cutoff_behavior(&self) -> &::std::option::Option<crate::types::MaintenanceWindowTaskCutoffBehavior> {
        &self.cutoff_behavior
    }
    /// <p>The details for the CloudWatch alarm applied to your maintenance window task.</p>
    pub fn alarm_configuration(mut self, input: crate::types::AlarmConfiguration) -> Self {
        self.alarm_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details for the CloudWatch alarm applied to your maintenance window task.</p>
    pub fn set_alarm_configuration(mut self, input: ::std::option::Option<crate::types::AlarmConfiguration>) -> Self {
        self.alarm_configuration = input;
        self
    }
    /// <p>The details for the CloudWatch alarm applied to your maintenance window task.</p>
    pub fn get_alarm_configuration(&self) -> &::std::option::Option<crate::types::AlarmConfiguration> {
        &self.alarm_configuration
    }
    /// Consumes the builder and constructs a [`MaintenanceWindowTask`](crate::types::MaintenanceWindowTask).
    pub fn build(self) -> crate::types::MaintenanceWindowTask {
        crate::types::MaintenanceWindowTask {
            window_id: self.window_id,
            window_task_id: self.window_task_id,
            task_arn: self.task_arn,
            r#type: self.r#type,
            targets: self.targets,
            task_parameters: self.task_parameters,
            priority: self.priority.unwrap_or_default(),
            logging_info: self.logging_info,
            service_role_arn: self.service_role_arn,
            max_concurrency: self.max_concurrency,
            max_errors: self.max_errors,
            name: self.name,
            description: self.description,
            cutoff_behavior: self.cutoff_behavior,
            alarm_configuration: self.alarm_configuration,
        }
    }
}
impl ::std::fmt::Debug for MaintenanceWindowTaskBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MaintenanceWindowTaskBuilder");
        formatter.field("window_id", &self.window_id);
        formatter.field("window_task_id", &self.window_task_id);
        formatter.field("task_arn", &self.task_arn);
        formatter.field("r#type", &self.r#type);
        formatter.field("targets", &self.targets);
        formatter.field("task_parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("priority", &self.priority);
        formatter.field("logging_info", &self.logging_info);
        formatter.field("service_role_arn", &self.service_role_arn);
        formatter.field("max_concurrency", &self.max_concurrency);
        formatter.field("max_errors", &self.max_errors);
        formatter.field("name", &self.name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("cutoff_behavior", &self.cutoff_behavior);
        formatter.field("alarm_configuration", &self.alarm_configuration);
        formatter.finish()
    }
}
