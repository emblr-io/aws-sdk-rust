// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>DescribeTaskResponse</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTaskOutput {
    /// <p>The ARN of your task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The status of your task. For information about what each status means, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-creation-statuses">Task statuses</a>.</p>
    pub status: ::std::option::Option<crate::types::TaskStatus>,
    /// <p>The name of your task.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the most recent task execution.</p>
    pub current_task_execution_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of your transfer's source location.</p>
    pub source_location_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of your transfer's destination location.</p>
    pub destination_location_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of an Amazon CloudWatch log group for monitoring your task.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-logging.html">Monitoring data transfers with CloudWatch Logs</a>.</p>
    pub cloud_watch_log_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your source location.</p>
    pub source_network_interface_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your destination location.</p>
    pub destination_network_interface_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The task's settings. For example, what file metadata gets preserved, how data integrity gets verified at the end of your transfer, bandwidth limits, among other options.</p>
    pub options: ::std::option::Option<crate::types::Options>,
    /// <p>The exclude filters that define the files, objects, and folders in your source location that you don't want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub excludes: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>,
    /// <p>The schedule for when you want your task to run. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">Scheduling your task</a>.</p>
    pub schedule: ::std::option::Option<crate::types::TaskSchedule>,
    /// <p>If there's an issue with your task, you can use the error code to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub error_code: ::std::option::Option<::std::string::String>,
    /// <p>If there's an issue with your task, you can use the error details to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub error_detail: ::std::option::Option<::std::string::String>,
    /// <p>The time that the task was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The include filters that define the files, objects, and folders in your source location that you want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub includes: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>,
    /// <p>The configuration of the manifest that lists the files or objects that you want DataSync to transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">Specifying what DataSync transfers by using a manifest</a>.</p>
    pub manifest_config: ::std::option::Option<crate::types::ManifestConfig>,
    /// <p>The configuration of your task report, which provides detailed information about your DataSync transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">Monitoring your DataSync transfers with task reports</a>.</p>
    pub task_report_config: ::std::option::Option<crate::types::TaskReportConfig>,
    /// <p>The details about your <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">task schedule</a>.</p>
    pub schedule_details: ::std::option::Option<crate::types::TaskScheduleDetails>,
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub task_mode: ::std::option::Option<crate::types::TaskMode>,
    _request_id: Option<String>,
}
impl DescribeTaskOutput {
    /// <p>The ARN of your task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
    /// <p>The status of your task. For information about what each status means, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-creation-statuses">Task statuses</a>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TaskStatus> {
        self.status.as_ref()
    }
    /// <p>The name of your task.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the most recent task execution.</p>
    pub fn current_task_execution_arn(&self) -> ::std::option::Option<&str> {
        self.current_task_execution_arn.as_deref()
    }
    /// <p>The ARN of your transfer's source location.</p>
    pub fn source_location_arn(&self) -> ::std::option::Option<&str> {
        self.source_location_arn.as_deref()
    }
    /// <p>The ARN of your transfer's destination location.</p>
    pub fn destination_location_arn(&self) -> ::std::option::Option<&str> {
        self.destination_location_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon CloudWatch log group for monitoring your task.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-logging.html">Monitoring data transfers with CloudWatch Logs</a>.</p>
    pub fn cloud_watch_log_group_arn(&self) -> ::std::option::Option<&str> {
        self.cloud_watch_log_group_arn.as_deref()
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your source location.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.source_network_interface_arns.is_none()`.
    pub fn source_network_interface_arns(&self) -> &[::std::string::String] {
        self.source_network_interface_arns.as_deref().unwrap_or_default()
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your destination location.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.destination_network_interface_arns.is_none()`.
    pub fn destination_network_interface_arns(&self) -> &[::std::string::String] {
        self.destination_network_interface_arns.as_deref().unwrap_or_default()
    }
    /// <p>The task's settings. For example, what file metadata gets preserved, how data integrity gets verified at the end of your transfer, bandwidth limits, among other options.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::Options> {
        self.options.as_ref()
    }
    /// <p>The exclude filters that define the files, objects, and folders in your source location that you don't want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.excludes.is_none()`.
    pub fn excludes(&self) -> &[crate::types::FilterRule] {
        self.excludes.as_deref().unwrap_or_default()
    }
    /// <p>The schedule for when you want your task to run. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">Scheduling your task</a>.</p>
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::TaskSchedule> {
        self.schedule.as_ref()
    }
    /// <p>If there's an issue with your task, you can use the error code to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn error_code(&self) -> ::std::option::Option<&str> {
        self.error_code.as_deref()
    }
    /// <p>If there's an issue with your task, you can use the error details to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn error_detail(&self) -> ::std::option::Option<&str> {
        self.error_detail.as_deref()
    }
    /// <p>The time that the task was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The include filters that define the files, objects, and folders in your source location that you want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.includes.is_none()`.
    pub fn includes(&self) -> &[crate::types::FilterRule] {
        self.includes.as_deref().unwrap_or_default()
    }
    /// <p>The configuration of the manifest that lists the files or objects that you want DataSync to transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">Specifying what DataSync transfers by using a manifest</a>.</p>
    pub fn manifest_config(&self) -> ::std::option::Option<&crate::types::ManifestConfig> {
        self.manifest_config.as_ref()
    }
    /// <p>The configuration of your task report, which provides detailed information about your DataSync transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">Monitoring your DataSync transfers with task reports</a>.</p>
    pub fn task_report_config(&self) -> ::std::option::Option<&crate::types::TaskReportConfig> {
        self.task_report_config.as_ref()
    }
    /// <p>The details about your <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">task schedule</a>.</p>
    pub fn schedule_details(&self) -> ::std::option::Option<&crate::types::TaskScheduleDetails> {
        self.schedule_details.as_ref()
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn task_mode(&self) -> ::std::option::Option<&crate::types::TaskMode> {
        self.task_mode.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTaskOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTaskOutput`](crate::operation::describe_task::DescribeTaskOutput).
    pub fn builder() -> crate::operation::describe_task::builders::DescribeTaskOutputBuilder {
        crate::operation::describe_task::builders::DescribeTaskOutputBuilder::default()
    }
}

/// A builder for [`DescribeTaskOutput`](crate::operation::describe_task::DescribeTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTaskOutputBuilder {
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::TaskStatus>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) current_task_execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) destination_location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) cloud_watch_log_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_network_interface_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) destination_network_interface_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) options: ::std::option::Option<crate::types::Options>,
    pub(crate) excludes: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>,
    pub(crate) schedule: ::std::option::Option<crate::types::TaskSchedule>,
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) error_detail: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) includes: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>,
    pub(crate) manifest_config: ::std::option::Option<crate::types::ManifestConfig>,
    pub(crate) task_report_config: ::std::option::Option<crate::types::TaskReportConfig>,
    pub(crate) schedule_details: ::std::option::Option<crate::types::TaskScheduleDetails>,
    pub(crate) task_mode: ::std::option::Option<crate::types::TaskMode>,
    _request_id: Option<String>,
}
impl DescribeTaskOutputBuilder {
    /// <p>The ARN of your task.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of your task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The ARN of your task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// <p>The status of your task. For information about what each status means, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-creation-statuses">Task statuses</a>.</p>
    pub fn status(mut self, input: crate::types::TaskStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of your task. For information about what each status means, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-creation-statuses">Task statuses</a>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TaskStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of your task. For information about what each status means, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-creation-statuses">Task statuses</a>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TaskStatus> {
        &self.status
    }
    /// <p>The name of your task.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your task.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of your task.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the most recent task execution.</p>
    pub fn current_task_execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_task_execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the most recent task execution.</p>
    pub fn set_current_task_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_task_execution_arn = input;
        self
    }
    /// <p>The ARN of the most recent task execution.</p>
    pub fn get_current_task_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_task_execution_arn
    }
    /// <p>The ARN of your transfer's source location.</p>
    pub fn source_location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of your transfer's source location.</p>
    pub fn set_source_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_location_arn = input;
        self
    }
    /// <p>The ARN of your transfer's source location.</p>
    pub fn get_source_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_location_arn
    }
    /// <p>The ARN of your transfer's destination location.</p>
    pub fn destination_location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of your transfer's destination location.</p>
    pub fn set_destination_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_location_arn = input;
        self
    }
    /// <p>The ARN of your transfer's destination location.</p>
    pub fn get_destination_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_location_arn
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon CloudWatch log group for monitoring your task.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-logging.html">Monitoring data transfers with CloudWatch Logs</a>.</p>
    pub fn cloud_watch_log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_watch_log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon CloudWatch log group for monitoring your task.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-logging.html">Monitoring data transfers with CloudWatch Logs</a>.</p>
    pub fn set_cloud_watch_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_watch_log_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Amazon CloudWatch log group for monitoring your task.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-logging.html">Monitoring data transfers with CloudWatch Logs</a>.</p>
    pub fn get_cloud_watch_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_watch_log_group_arn
    }
    /// Appends an item to `source_network_interface_arns`.
    ///
    /// To override the contents of this collection use [`set_source_network_interface_arns`](Self::set_source_network_interface_arns).
    ///
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your source location.</p>
    pub fn source_network_interface_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.source_network_interface_arns.unwrap_or_default();
        v.push(input.into());
        self.source_network_interface_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your source location.</p>
    pub fn set_source_network_interface_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.source_network_interface_arns = input;
        self
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your source location.</p>
    pub fn get_source_network_interface_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.source_network_interface_arns
    }
    /// Appends an item to `destination_network_interface_arns`.
    ///
    /// To override the contents of this collection use [`set_destination_network_interface_arns`](Self::set_destination_network_interface_arns).
    ///
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your destination location.</p>
    pub fn destination_network_interface_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.destination_network_interface_arns.unwrap_or_default();
        v.push(input.into());
        self.destination_network_interface_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your destination location.</p>
    pub fn set_destination_network_interface_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.destination_network_interface_arns = input;
        self
    }
    /// <p>The ARNs of the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/datasync-network.html#required-network-interfaces">network interfaces</a> that DataSync created for your destination location.</p>
    pub fn get_destination_network_interface_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.destination_network_interface_arns
    }
    /// <p>The task's settings. For example, what file metadata gets preserved, how data integrity gets verified at the end of your transfer, bandwidth limits, among other options.</p>
    pub fn options(mut self, input: crate::types::Options) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The task's settings. For example, what file metadata gets preserved, how data integrity gets verified at the end of your transfer, bandwidth limits, among other options.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::Options>) -> Self {
        self.options = input;
        self
    }
    /// <p>The task's settings. For example, what file metadata gets preserved, how data integrity gets verified at the end of your transfer, bandwidth limits, among other options.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::Options> {
        &self.options
    }
    /// Appends an item to `excludes`.
    ///
    /// To override the contents of this collection use [`set_excludes`](Self::set_excludes).
    ///
    /// <p>The exclude filters that define the files, objects, and folders in your source location that you don't want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn excludes(mut self, input: crate::types::FilterRule) -> Self {
        let mut v = self.excludes.unwrap_or_default();
        v.push(input);
        self.excludes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The exclude filters that define the files, objects, and folders in your source location that you don't want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn set_excludes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>) -> Self {
        self.excludes = input;
        self
    }
    /// <p>The exclude filters that define the files, objects, and folders in your source location that you don't want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn get_excludes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterRule>> {
        &self.excludes
    }
    /// <p>The schedule for when you want your task to run. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">Scheduling your task</a>.</p>
    pub fn schedule(mut self, input: crate::types::TaskSchedule) -> Self {
        self.schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schedule for when you want your task to run. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">Scheduling your task</a>.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<crate::types::TaskSchedule>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The schedule for when you want your task to run. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">Scheduling your task</a>.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<crate::types::TaskSchedule> {
        &self.schedule
    }
    /// <p>If there's an issue with your task, you can use the error code to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there's an issue with your task, you can use the error code to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>If there's an issue with your task, you can use the error code to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>If there's an issue with your task, you can use the error details to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn error_detail(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_detail = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there's an issue with your task, you can use the error details to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn set_error_detail(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_detail = input;
        self
    }
    /// <p>If there's an issue with your task, you can use the error details to help you troubleshoot the problem. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/troubleshooting-datasync-locations-tasks.html">Troubleshooting issues with DataSync transfers</a>.</p>
    pub fn get_error_detail(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_detail
    }
    /// <p>The time that the task was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the task was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that the task was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// Appends an item to `includes`.
    ///
    /// To override the contents of this collection use [`set_includes`](Self::set_includes).
    ///
    /// <p>The include filters that define the files, objects, and folders in your source location that you want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn includes(mut self, input: crate::types::FilterRule) -> Self {
        let mut v = self.includes.unwrap_or_default();
        v.push(input);
        self.includes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The include filters that define the files, objects, and folders in your source location that you want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn set_includes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterRule>>) -> Self {
        self.includes = input;
        self
    }
    /// <p>The include filters that define the files, objects, and folders in your source location that you want DataSync to transfer. For more information and examples, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">Specifying what DataSync transfers by using filters</a>.</p>
    pub fn get_includes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterRule>> {
        &self.includes
    }
    /// <p>The configuration of the manifest that lists the files or objects that you want DataSync to transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">Specifying what DataSync transfers by using a manifest</a>.</p>
    pub fn manifest_config(mut self, input: crate::types::ManifestConfig) -> Self {
        self.manifest_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration of the manifest that lists the files or objects that you want DataSync to transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">Specifying what DataSync transfers by using a manifest</a>.</p>
    pub fn set_manifest_config(mut self, input: ::std::option::Option<crate::types::ManifestConfig>) -> Self {
        self.manifest_config = input;
        self
    }
    /// <p>The configuration of the manifest that lists the files or objects that you want DataSync to transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">Specifying what DataSync transfers by using a manifest</a>.</p>
    pub fn get_manifest_config(&self) -> &::std::option::Option<crate::types::ManifestConfig> {
        &self.manifest_config
    }
    /// <p>The configuration of your task report, which provides detailed information about your DataSync transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">Monitoring your DataSync transfers with task reports</a>.</p>
    pub fn task_report_config(mut self, input: crate::types::TaskReportConfig) -> Self {
        self.task_report_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration of your task report, which provides detailed information about your DataSync transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">Monitoring your DataSync transfers with task reports</a>.</p>
    pub fn set_task_report_config(mut self, input: ::std::option::Option<crate::types::TaskReportConfig>) -> Self {
        self.task_report_config = input;
        self
    }
    /// <p>The configuration of your task report, which provides detailed information about your DataSync transfer. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-reports.html">Monitoring your DataSync transfers with task reports</a>.</p>
    pub fn get_task_report_config(&self) -> &::std::option::Option<crate::types::TaskReportConfig> {
        &self.task_report_config
    }
    /// <p>The details about your <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">task schedule</a>.</p>
    pub fn schedule_details(mut self, input: crate::types::TaskScheduleDetails) -> Self {
        self.schedule_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details about your <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">task schedule</a>.</p>
    pub fn set_schedule_details(mut self, input: ::std::option::Option<crate::types::TaskScheduleDetails>) -> Self {
        self.schedule_details = input;
        self
    }
    /// <p>The details about your <a href="https://docs.aws.amazon.com/datasync/latest/userguide/task-scheduling.html">task schedule</a>.</p>
    pub fn get_schedule_details(&self) -> &::std::option::Option<crate::types::TaskScheduleDetails> {
        &self.schedule_details
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn task_mode(mut self, input: crate::types::TaskMode) -> Self {
        self.task_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn set_task_mode(mut self, input: ::std::option::Option<crate::types::TaskMode>) -> Self {
        self.task_mode = input;
        self
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn get_task_mode(&self) -> &::std::option::Option<crate::types::TaskMode> {
        &self.task_mode
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeTaskOutput`](crate::operation::describe_task::DescribeTaskOutput).
    pub fn build(self) -> crate::operation::describe_task::DescribeTaskOutput {
        crate::operation::describe_task::DescribeTaskOutput {
            task_arn: self.task_arn,
            status: self.status,
            name: self.name,
            current_task_execution_arn: self.current_task_execution_arn,
            source_location_arn: self.source_location_arn,
            destination_location_arn: self.destination_location_arn,
            cloud_watch_log_group_arn: self.cloud_watch_log_group_arn,
            source_network_interface_arns: self.source_network_interface_arns,
            destination_network_interface_arns: self.destination_network_interface_arns,
            options: self.options,
            excludes: self.excludes,
            schedule: self.schedule,
            error_code: self.error_code,
            error_detail: self.error_detail,
            creation_time: self.creation_time,
            includes: self.includes,
            manifest_config: self.manifest_config,
            task_report_config: self.task_report_config,
            schedule_details: self.schedule_details,
            task_mode: self.task_mode,
            _request_id: self._request_id,
        }
    }
}
