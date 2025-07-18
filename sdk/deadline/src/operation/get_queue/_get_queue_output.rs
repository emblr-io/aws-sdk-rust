// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetQueueOutput {
    /// <p>The queue ID.</p>
    pub queue_id: ::std::string::String,
    /// <p>The display name of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub display_name: ::std::string::String,
    /// <p>The description of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The farm ID for the queue.</p>
    pub farm_id: ::std::string::String,
    /// <p>The status of the queue.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code>–The queue is active.</p></li>
    /// <li>
    /// <p><code>SCHEDULING</code>–The queue is scheduling.</p></li>
    /// <li>
    /// <p><code>SCHEDULING_BLOCKED</code>–The queue scheduling is blocked. See the provided reason.</p></li>
    /// </ul>
    pub status: crate::types::QueueStatus,
    /// <p>The default action taken on a queue if a budget wasn't configured.</p>
    pub default_budget_action: crate::types::DefaultQueueBudgetAction,
    /// <p>The reason the queue was blocked.</p>
    pub blocked_reason: ::std::option::Option<crate::types::QueueBlockedReason>,
    /// <p>The job attachment settings for the queue.</p>
    pub job_attachment_settings: ::std::option::Option<crate::types::JobAttachmentSettings>,
    /// <p>The IAM role ARN.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of the required file system location names in the queue.</p>
    pub required_file_system_location_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The storage profile IDs for the queue.</p>
    pub allowed_storage_profile_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The jobs in the queue ran as this specified POSIX user.</p>
    pub job_run_as_user: ::std::option::Option<crate::types::JobRunAsUser>,
    /// <p>The date and time the resource was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The user or system that created this resource.</p>
    pub created_by: ::std::string::String,
    /// <p>The date and time the resource was updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The user or system that updated this resource.</p>
    pub updated_by: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueueOutput {
    /// <p>The queue ID.</p>
    pub fn queue_id(&self) -> &str {
        use std::ops::Deref;
        self.queue_id.deref()
    }
    /// <p>The display name of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn display_name(&self) -> &str {
        use std::ops::Deref;
        self.display_name.deref()
    }
    /// <p>The description of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The farm ID for the queue.</p>
    pub fn farm_id(&self) -> &str {
        use std::ops::Deref;
        self.farm_id.deref()
    }
    /// <p>The status of the queue.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code>–The queue is active.</p></li>
    /// <li>
    /// <p><code>SCHEDULING</code>–The queue is scheduling.</p></li>
    /// <li>
    /// <p><code>SCHEDULING_BLOCKED</code>–The queue scheduling is blocked. See the provided reason.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::QueueStatus {
        &self.status
    }
    /// <p>The default action taken on a queue if a budget wasn't configured.</p>
    pub fn default_budget_action(&self) -> &crate::types::DefaultQueueBudgetAction {
        &self.default_budget_action
    }
    /// <p>The reason the queue was blocked.</p>
    pub fn blocked_reason(&self) -> ::std::option::Option<&crate::types::QueueBlockedReason> {
        self.blocked_reason.as_ref()
    }
    /// <p>The job attachment settings for the queue.</p>
    pub fn job_attachment_settings(&self) -> ::std::option::Option<&crate::types::JobAttachmentSettings> {
        self.job_attachment_settings.as_ref()
    }
    /// <p>The IAM role ARN.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A list of the required file system location names in the queue.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.required_file_system_location_names.is_none()`.
    pub fn required_file_system_location_names(&self) -> &[::std::string::String] {
        self.required_file_system_location_names.as_deref().unwrap_or_default()
    }
    /// <p>The storage profile IDs for the queue.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_storage_profile_ids.is_none()`.
    pub fn allowed_storage_profile_ids(&self) -> &[::std::string::String] {
        self.allowed_storage_profile_ids.as_deref().unwrap_or_default()
    }
    /// <p>The jobs in the queue ran as this specified POSIX user.</p>
    pub fn job_run_as_user(&self) -> ::std::option::Option<&crate::types::JobRunAsUser> {
        self.job_run_as_user.as_ref()
    }
    /// <p>The date and time the resource was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The user or system that created this resource.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The date and time the resource was updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The user or system that updated this resource.</p>
    pub fn updated_by(&self) -> ::std::option::Option<&str> {
        self.updated_by.as_deref()
    }
}
impl ::std::fmt::Debug for GetQueueOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetQueueOutput");
        formatter.field("queue_id", &self.queue_id);
        formatter.field("display_name", &self.display_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("farm_id", &self.farm_id);
        formatter.field("status", &self.status);
        formatter.field("default_budget_action", &self.default_budget_action);
        formatter.field("blocked_reason", &self.blocked_reason);
        formatter.field("job_attachment_settings", &self.job_attachment_settings);
        formatter.field("role_arn", &self.role_arn);
        formatter.field("required_file_system_location_names", &self.required_file_system_location_names);
        formatter.field("allowed_storage_profile_ids", &self.allowed_storage_profile_ids);
        formatter.field("job_run_as_user", &self.job_run_as_user);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("updated_at", &self.updated_at);
        formatter.field("updated_by", &self.updated_by);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetQueueOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetQueueOutput {
    /// Creates a new builder-style object to manufacture [`GetQueueOutput`](crate::operation::get_queue::GetQueueOutput).
    pub fn builder() -> crate::operation::get_queue::builders::GetQueueOutputBuilder {
        crate::operation::get_queue::builders::GetQueueOutputBuilder::default()
    }
}

/// A builder for [`GetQueueOutput`](crate::operation::get_queue::GetQueueOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetQueueOutputBuilder {
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::QueueStatus>,
    pub(crate) default_budget_action: ::std::option::Option<crate::types::DefaultQueueBudgetAction>,
    pub(crate) blocked_reason: ::std::option::Option<crate::types::QueueBlockedReason>,
    pub(crate) job_attachment_settings: ::std::option::Option<crate::types::JobAttachmentSettings>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) required_file_system_location_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) allowed_storage_profile_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) job_run_as_user: ::std::option::Option<crate::types::JobRunAsUser>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetQueueOutputBuilder {
    /// <p>The queue ID.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The display name of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    /// This field is required.
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The description of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the queue.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The farm ID for the queue.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID for the queue.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID for the queue.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The status of the queue.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code>–The queue is active.</p></li>
    /// <li>
    /// <p><code>SCHEDULING</code>–The queue is scheduling.</p></li>
    /// <li>
    /// <p><code>SCHEDULING_BLOCKED</code>–The queue scheduling is blocked. See the provided reason.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::QueueStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the queue.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code>–The queue is active.</p></li>
    /// <li>
    /// <p><code>SCHEDULING</code>–The queue is scheduling.</p></li>
    /// <li>
    /// <p><code>SCHEDULING_BLOCKED</code>–The queue scheduling is blocked. See the provided reason.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::QueueStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the queue.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code>–The queue is active.</p></li>
    /// <li>
    /// <p><code>SCHEDULING</code>–The queue is scheduling.</p></li>
    /// <li>
    /// <p><code>SCHEDULING_BLOCKED</code>–The queue scheduling is blocked. See the provided reason.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::QueueStatus> {
        &self.status
    }
    /// <p>The default action taken on a queue if a budget wasn't configured.</p>
    /// This field is required.
    pub fn default_budget_action(mut self, input: crate::types::DefaultQueueBudgetAction) -> Self {
        self.default_budget_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default action taken on a queue if a budget wasn't configured.</p>
    pub fn set_default_budget_action(mut self, input: ::std::option::Option<crate::types::DefaultQueueBudgetAction>) -> Self {
        self.default_budget_action = input;
        self
    }
    /// <p>The default action taken on a queue if a budget wasn't configured.</p>
    pub fn get_default_budget_action(&self) -> &::std::option::Option<crate::types::DefaultQueueBudgetAction> {
        &self.default_budget_action
    }
    /// <p>The reason the queue was blocked.</p>
    pub fn blocked_reason(mut self, input: crate::types::QueueBlockedReason) -> Self {
        self.blocked_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason the queue was blocked.</p>
    pub fn set_blocked_reason(mut self, input: ::std::option::Option<crate::types::QueueBlockedReason>) -> Self {
        self.blocked_reason = input;
        self
    }
    /// <p>The reason the queue was blocked.</p>
    pub fn get_blocked_reason(&self) -> &::std::option::Option<crate::types::QueueBlockedReason> {
        &self.blocked_reason
    }
    /// <p>The job attachment settings for the queue.</p>
    pub fn job_attachment_settings(mut self, input: crate::types::JobAttachmentSettings) -> Self {
        self.job_attachment_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The job attachment settings for the queue.</p>
    pub fn set_job_attachment_settings(mut self, input: ::std::option::Option<crate::types::JobAttachmentSettings>) -> Self {
        self.job_attachment_settings = input;
        self
    }
    /// <p>The job attachment settings for the queue.</p>
    pub fn get_job_attachment_settings(&self) -> &::std::option::Option<crate::types::JobAttachmentSettings> {
        &self.job_attachment_settings
    }
    /// <p>The IAM role ARN.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role ARN.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The IAM role ARN.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Appends an item to `required_file_system_location_names`.
    ///
    /// To override the contents of this collection use [`set_required_file_system_location_names`](Self::set_required_file_system_location_names).
    ///
    /// <p>A list of the required file system location names in the queue.</p>
    pub fn required_file_system_location_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.required_file_system_location_names.unwrap_or_default();
        v.push(input.into());
        self.required_file_system_location_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the required file system location names in the queue.</p>
    pub fn set_required_file_system_location_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.required_file_system_location_names = input;
        self
    }
    /// <p>A list of the required file system location names in the queue.</p>
    pub fn get_required_file_system_location_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.required_file_system_location_names
    }
    /// Appends an item to `allowed_storage_profile_ids`.
    ///
    /// To override the contents of this collection use [`set_allowed_storage_profile_ids`](Self::set_allowed_storage_profile_ids).
    ///
    /// <p>The storage profile IDs for the queue.</p>
    pub fn allowed_storage_profile_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.allowed_storage_profile_ids.unwrap_or_default();
        v.push(input.into());
        self.allowed_storage_profile_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The storage profile IDs for the queue.</p>
    pub fn set_allowed_storage_profile_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.allowed_storage_profile_ids = input;
        self
    }
    /// <p>The storage profile IDs for the queue.</p>
    pub fn get_allowed_storage_profile_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.allowed_storage_profile_ids
    }
    /// <p>The jobs in the queue ran as this specified POSIX user.</p>
    pub fn job_run_as_user(mut self, input: crate::types::JobRunAsUser) -> Self {
        self.job_run_as_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>The jobs in the queue ran as this specified POSIX user.</p>
    pub fn set_job_run_as_user(mut self, input: ::std::option::Option<crate::types::JobRunAsUser>) -> Self {
        self.job_run_as_user = input;
        self
    }
    /// <p>The jobs in the queue ran as this specified POSIX user.</p>
    pub fn get_job_run_as_user(&self) -> &::std::option::Option<crate::types::JobRunAsUser> {
        &self.job_run_as_user
    }
    /// <p>The date and time the resource was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the resource was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time the resource was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The user or system that created this resource.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user or system that created this resource.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user or system that created this resource.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The date and time the resource was updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the resource was updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time the resource was updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The user or system that updated this resource.</p>
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user or system that updated this resource.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The user or system that updated this resource.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetQueueOutput`](crate::operation::get_queue::GetQueueOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`queue_id`](crate::operation::get_queue::builders::GetQueueOutputBuilder::queue_id)
    /// - [`display_name`](crate::operation::get_queue::builders::GetQueueOutputBuilder::display_name)
    /// - [`farm_id`](crate::operation::get_queue::builders::GetQueueOutputBuilder::farm_id)
    /// - [`status`](crate::operation::get_queue::builders::GetQueueOutputBuilder::status)
    /// - [`default_budget_action`](crate::operation::get_queue::builders::GetQueueOutputBuilder::default_budget_action)
    /// - [`created_at`](crate::operation::get_queue::builders::GetQueueOutputBuilder::created_at)
    /// - [`created_by`](crate::operation::get_queue::builders::GetQueueOutputBuilder::created_by)
    pub fn build(self) -> ::std::result::Result<crate::operation::get_queue::GetQueueOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_queue::GetQueueOutput {
            queue_id: self.queue_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "queue_id",
                    "queue_id was not specified but it is required when building GetQueueOutput",
                )
            })?,
            display_name: self.display_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "display_name",
                    "display_name was not specified but it is required when building GetQueueOutput",
                )
            })?,
            description: self.description,
            farm_id: self.farm_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "farm_id",
                    "farm_id was not specified but it is required when building GetQueueOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetQueueOutput",
                )
            })?,
            default_budget_action: self.default_budget_action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "default_budget_action",
                    "default_budget_action was not specified but it is required when building GetQueueOutput",
                )
            })?,
            blocked_reason: self.blocked_reason,
            job_attachment_settings: self.job_attachment_settings,
            role_arn: self.role_arn,
            required_file_system_location_names: self.required_file_system_location_names,
            allowed_storage_profile_ids: self.allowed_storage_profile_ids,
            job_run_as_user: self.job_run_as_user,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetQueueOutput",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building GetQueueOutput",
                )
            })?,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            _request_id: self._request_id,
        })
    }
}
impl ::std::fmt::Debug for GetQueueOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetQueueOutputBuilder");
        formatter.field("queue_id", &self.queue_id);
        formatter.field("display_name", &self.display_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("farm_id", &self.farm_id);
        formatter.field("status", &self.status);
        formatter.field("default_budget_action", &self.default_budget_action);
        formatter.field("blocked_reason", &self.blocked_reason);
        formatter.field("job_attachment_settings", &self.job_attachment_settings);
        formatter.field("role_arn", &self.role_arn);
        formatter.field("required_file_system_location_names", &self.required_file_system_location_names);
        formatter.field("allowed_storage_profile_ids", &self.allowed_storage_profile_ids);
        formatter.field("job_run_as_user", &self.job_run_as_user);
        formatter.field("created_at", &self.created_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("updated_at", &self.updated_at);
        formatter.field("updated_by", &self.updated_by);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
