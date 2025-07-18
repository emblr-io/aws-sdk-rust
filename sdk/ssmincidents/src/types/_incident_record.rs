// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The record of the incident that's created when an incident occurs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IncidentRecord {
    /// <p>The Amazon Resource Name (ARN) of the incident record.</p>
    pub arn: ::std::string::String,
    /// <p>The title of the incident.</p>
    pub title: ::std::string::String,
    /// <p>The summary of the incident. The summary is a brief synopsis of what occurred, what's currently happening, and context of the incident.</p>
    pub summary: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the incident.</p>
    pub status: crate::types::IncidentRecordStatus,
    /// <p>The impact of the incident on customers and applications.</p>
    /// <p class="title"><b>Supported impact codes</b></p>
    /// <ul>
    /// <li>
    /// <p><code>1</code> - Critical</p></li>
    /// <li>
    /// <p><code>2</code> - High</p></li>
    /// <li>
    /// <p><code>3</code> - Medium</p></li>
    /// <li>
    /// <p><code>4</code> - Low</p></li>
    /// <li>
    /// <p><code>5</code> - No Impact</p></li>
    /// </ul>
    pub impact: i32,
    /// <p>The timestamp for when Incident Manager created the incident record.</p>
    pub creation_time: ::aws_smithy_types::DateTime,
    /// <p>The timestamp for when the incident was resolved. This appears as a timeline event.</p>
    pub resolved_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp for when the incident was most recently modified.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
    /// <p>Who modified the incident most recently.</p>
    pub last_modified_by: ::std::string::String,
    /// <p>The runbook, or automation document, that's run at the beginning of the incident.</p>
    pub automation_executions: ::std::option::Option<::std::vec::Vec<crate::types::AutomationExecution>>,
    /// <p>Details about the action that started the incident.</p>
    pub incident_record_source: ::std::option::Option<crate::types::IncidentRecordSource>,
    /// <p>The string Incident Manager uses to prevent duplicate incidents from being created by the same incident in the same account.</p>
    pub dedupe_string: ::std::string::String,
    /// <p>The chat channel used for collaboration during an incident.</p>
    pub chat_channel: ::std::option::Option<crate::types::ChatChannel>,
    /// <p>The Amazon SNS targets that are notified when updates are made to an incident.</p>
    pub notification_targets: ::std::option::Option<::std::vec::Vec<crate::types::NotificationTargetItem>>,
}
impl IncidentRecord {
    /// <p>The Amazon Resource Name (ARN) of the incident record.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The title of the incident.</p>
    pub fn title(&self) -> &str {
        use std::ops::Deref;
        self.title.deref()
    }
    /// <p>The summary of the incident. The summary is a brief synopsis of what occurred, what's currently happening, and context of the incident.</p>
    pub fn summary(&self) -> ::std::option::Option<&str> {
        self.summary.as_deref()
    }
    /// <p>The current status of the incident.</p>
    pub fn status(&self) -> &crate::types::IncidentRecordStatus {
        &self.status
    }
    /// <p>The impact of the incident on customers and applications.</p>
    /// <p class="title"><b>Supported impact codes</b></p>
    /// <ul>
    /// <li>
    /// <p><code>1</code> - Critical</p></li>
    /// <li>
    /// <p><code>2</code> - High</p></li>
    /// <li>
    /// <p><code>3</code> - Medium</p></li>
    /// <li>
    /// <p><code>4</code> - Low</p></li>
    /// <li>
    /// <p><code>5</code> - No Impact</p></li>
    /// </ul>
    pub fn impact(&self) -> i32 {
        self.impact
    }
    /// <p>The timestamp for when Incident Manager created the incident record.</p>
    pub fn creation_time(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_time
    }
    /// <p>The timestamp for when the incident was resolved. This appears as a timeline event.</p>
    pub fn resolved_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.resolved_time.as_ref()
    }
    /// <p>The timestamp for when the incident was most recently modified.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
    /// <p>Who modified the incident most recently.</p>
    pub fn last_modified_by(&self) -> &str {
        use std::ops::Deref;
        self.last_modified_by.deref()
    }
    /// <p>The runbook, or automation document, that's run at the beginning of the incident.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.automation_executions.is_none()`.
    pub fn automation_executions(&self) -> &[crate::types::AutomationExecution] {
        self.automation_executions.as_deref().unwrap_or_default()
    }
    /// <p>Details about the action that started the incident.</p>
    pub fn incident_record_source(&self) -> ::std::option::Option<&crate::types::IncidentRecordSource> {
        self.incident_record_source.as_ref()
    }
    /// <p>The string Incident Manager uses to prevent duplicate incidents from being created by the same incident in the same account.</p>
    pub fn dedupe_string(&self) -> &str {
        use std::ops::Deref;
        self.dedupe_string.deref()
    }
    /// <p>The chat channel used for collaboration during an incident.</p>
    pub fn chat_channel(&self) -> ::std::option::Option<&crate::types::ChatChannel> {
        self.chat_channel.as_ref()
    }
    /// <p>The Amazon SNS targets that are notified when updates are made to an incident.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notification_targets.is_none()`.
    pub fn notification_targets(&self) -> &[crate::types::NotificationTargetItem] {
        self.notification_targets.as_deref().unwrap_or_default()
    }
}
impl IncidentRecord {
    /// Creates a new builder-style object to manufacture [`IncidentRecord`](crate::types::IncidentRecord).
    pub fn builder() -> crate::types::builders::IncidentRecordBuilder {
        crate::types::builders::IncidentRecordBuilder::default()
    }
}

/// A builder for [`IncidentRecord`](crate::types::IncidentRecord).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IncidentRecordBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) summary: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::IncidentRecordStatus>,
    pub(crate) impact: ::std::option::Option<i32>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) resolved_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_by: ::std::option::Option<::std::string::String>,
    pub(crate) automation_executions: ::std::option::Option<::std::vec::Vec<crate::types::AutomationExecution>>,
    pub(crate) incident_record_source: ::std::option::Option<crate::types::IncidentRecordSource>,
    pub(crate) dedupe_string: ::std::option::Option<::std::string::String>,
    pub(crate) chat_channel: ::std::option::Option<crate::types::ChatChannel>,
    pub(crate) notification_targets: ::std::option::Option<::std::vec::Vec<crate::types::NotificationTargetItem>>,
}
impl IncidentRecordBuilder {
    /// <p>The Amazon Resource Name (ARN) of the incident record.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the incident record.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the incident record.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The title of the incident.</p>
    /// This field is required.
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the incident.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the incident.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The summary of the incident. The summary is a brief synopsis of what occurred, what's currently happening, and context of the incident.</p>
    pub fn summary(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.summary = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The summary of the incident. The summary is a brief synopsis of what occurred, what's currently happening, and context of the incident.</p>
    pub fn set_summary(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.summary = input;
        self
    }
    /// <p>The summary of the incident. The summary is a brief synopsis of what occurred, what's currently happening, and context of the incident.</p>
    pub fn get_summary(&self) -> &::std::option::Option<::std::string::String> {
        &self.summary
    }
    /// <p>The current status of the incident.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::IncidentRecordStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the incident.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::IncidentRecordStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the incident.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::IncidentRecordStatus> {
        &self.status
    }
    /// <p>The impact of the incident on customers and applications.</p>
    /// <p class="title"><b>Supported impact codes</b></p>
    /// <ul>
    /// <li>
    /// <p><code>1</code> - Critical</p></li>
    /// <li>
    /// <p><code>2</code> - High</p></li>
    /// <li>
    /// <p><code>3</code> - Medium</p></li>
    /// <li>
    /// <p><code>4</code> - Low</p></li>
    /// <li>
    /// <p><code>5</code> - No Impact</p></li>
    /// </ul>
    /// This field is required.
    pub fn impact(mut self, input: i32) -> Self {
        self.impact = ::std::option::Option::Some(input);
        self
    }
    /// <p>The impact of the incident on customers and applications.</p>
    /// <p class="title"><b>Supported impact codes</b></p>
    /// <ul>
    /// <li>
    /// <p><code>1</code> - Critical</p></li>
    /// <li>
    /// <p><code>2</code> - High</p></li>
    /// <li>
    /// <p><code>3</code> - Medium</p></li>
    /// <li>
    /// <p><code>4</code> - Low</p></li>
    /// <li>
    /// <p><code>5</code> - No Impact</p></li>
    /// </ul>
    pub fn set_impact(mut self, input: ::std::option::Option<i32>) -> Self {
        self.impact = input;
        self
    }
    /// <p>The impact of the incident on customers and applications.</p>
    /// <p class="title"><b>Supported impact codes</b></p>
    /// <ul>
    /// <li>
    /// <p><code>1</code> - Critical</p></li>
    /// <li>
    /// <p><code>2</code> - High</p></li>
    /// <li>
    /// <p><code>3</code> - Medium</p></li>
    /// <li>
    /// <p><code>4</code> - Low</p></li>
    /// <li>
    /// <p><code>5</code> - No Impact</p></li>
    /// </ul>
    pub fn get_impact(&self) -> &::std::option::Option<i32> {
        &self.impact
    }
    /// <p>The timestamp for when Incident Manager created the incident record.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when Incident Manager created the incident record.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The timestamp for when Incident Manager created the incident record.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The timestamp for when the incident was resolved. This appears as a timeline event.</p>
    pub fn resolved_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.resolved_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the incident was resolved. This appears as a timeline event.</p>
    pub fn set_resolved_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.resolved_time = input;
        self
    }
    /// <p>The timestamp for when the incident was resolved. This appears as a timeline event.</p>
    pub fn get_resolved_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.resolved_time
    }
    /// <p>The timestamp for when the incident was most recently modified.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the incident was most recently modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp for when the incident was most recently modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>Who modified the incident most recently.</p>
    /// This field is required.
    pub fn last_modified_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Who modified the incident most recently.</p>
    pub fn set_last_modified_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_by = input;
        self
    }
    /// <p>Who modified the incident most recently.</p>
    pub fn get_last_modified_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_by
    }
    /// Appends an item to `automation_executions`.
    ///
    /// To override the contents of this collection use [`set_automation_executions`](Self::set_automation_executions).
    ///
    /// <p>The runbook, or automation document, that's run at the beginning of the incident.</p>
    pub fn automation_executions(mut self, input: crate::types::AutomationExecution) -> Self {
        let mut v = self.automation_executions.unwrap_or_default();
        v.push(input);
        self.automation_executions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The runbook, or automation document, that's run at the beginning of the incident.</p>
    pub fn set_automation_executions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AutomationExecution>>) -> Self {
        self.automation_executions = input;
        self
    }
    /// <p>The runbook, or automation document, that's run at the beginning of the incident.</p>
    pub fn get_automation_executions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutomationExecution>> {
        &self.automation_executions
    }
    /// <p>Details about the action that started the incident.</p>
    /// This field is required.
    pub fn incident_record_source(mut self, input: crate::types::IncidentRecordSource) -> Self {
        self.incident_record_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the action that started the incident.</p>
    pub fn set_incident_record_source(mut self, input: ::std::option::Option<crate::types::IncidentRecordSource>) -> Self {
        self.incident_record_source = input;
        self
    }
    /// <p>Details about the action that started the incident.</p>
    pub fn get_incident_record_source(&self) -> &::std::option::Option<crate::types::IncidentRecordSource> {
        &self.incident_record_source
    }
    /// <p>The string Incident Manager uses to prevent duplicate incidents from being created by the same incident in the same account.</p>
    /// This field is required.
    pub fn dedupe_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dedupe_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string Incident Manager uses to prevent duplicate incidents from being created by the same incident in the same account.</p>
    pub fn set_dedupe_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dedupe_string = input;
        self
    }
    /// <p>The string Incident Manager uses to prevent duplicate incidents from being created by the same incident in the same account.</p>
    pub fn get_dedupe_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.dedupe_string
    }
    /// <p>The chat channel used for collaboration during an incident.</p>
    pub fn chat_channel(mut self, input: crate::types::ChatChannel) -> Self {
        self.chat_channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The chat channel used for collaboration during an incident.</p>
    pub fn set_chat_channel(mut self, input: ::std::option::Option<crate::types::ChatChannel>) -> Self {
        self.chat_channel = input;
        self
    }
    /// <p>The chat channel used for collaboration during an incident.</p>
    pub fn get_chat_channel(&self) -> &::std::option::Option<crate::types::ChatChannel> {
        &self.chat_channel
    }
    /// Appends an item to `notification_targets`.
    ///
    /// To override the contents of this collection use [`set_notification_targets`](Self::set_notification_targets).
    ///
    /// <p>The Amazon SNS targets that are notified when updates are made to an incident.</p>
    pub fn notification_targets(mut self, input: crate::types::NotificationTargetItem) -> Self {
        let mut v = self.notification_targets.unwrap_or_default();
        v.push(input);
        self.notification_targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon SNS targets that are notified when updates are made to an incident.</p>
    pub fn set_notification_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotificationTargetItem>>) -> Self {
        self.notification_targets = input;
        self
    }
    /// <p>The Amazon SNS targets that are notified when updates are made to an incident.</p>
    pub fn get_notification_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotificationTargetItem>> {
        &self.notification_targets
    }
    /// Consumes the builder and constructs a [`IncidentRecord`](crate::types::IncidentRecord).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::IncidentRecordBuilder::arn)
    /// - [`title`](crate::types::builders::IncidentRecordBuilder::title)
    /// - [`status`](crate::types::builders::IncidentRecordBuilder::status)
    /// - [`impact`](crate::types::builders::IncidentRecordBuilder::impact)
    /// - [`creation_time`](crate::types::builders::IncidentRecordBuilder::creation_time)
    /// - [`last_modified_time`](crate::types::builders::IncidentRecordBuilder::last_modified_time)
    /// - [`last_modified_by`](crate::types::builders::IncidentRecordBuilder::last_modified_by)
    /// - [`dedupe_string`](crate::types::builders::IncidentRecordBuilder::dedupe_string)
    pub fn build(self) -> ::std::result::Result<crate::types::IncidentRecord, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IncidentRecord {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building IncidentRecord",
                )
            })?,
            title: self.title.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "title",
                    "title was not specified but it is required when building IncidentRecord",
                )
            })?,
            summary: self.summary,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building IncidentRecord",
                )
            })?,
            impact: self.impact.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "impact",
                    "impact was not specified but it is required when building IncidentRecord",
                )
            })?,
            creation_time: self.creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_time",
                    "creation_time was not specified but it is required when building IncidentRecord",
                )
            })?,
            resolved_time: self.resolved_time,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building IncidentRecord",
                )
            })?,
            last_modified_by: self.last_modified_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_by",
                    "last_modified_by was not specified but it is required when building IncidentRecord",
                )
            })?,
            automation_executions: self.automation_executions,
            incident_record_source: self.incident_record_source,
            dedupe_string: self.dedupe_string.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dedupe_string",
                    "dedupe_string was not specified but it is required when building IncidentRecord",
                )
            })?,
            chat_channel: self.chat_channel,
            notification_targets: self.notification_targets,
        })
    }
}
