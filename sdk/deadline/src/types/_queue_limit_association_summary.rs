// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the association between a queue and a limit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueueLimitAssociationSummary {
    /// <p>The Unix timestamp of the date and time that the association was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The user identifier of the person that created the association.</p>
    pub created_by: ::std::string::String,
    /// <p>The Unix timestamp of the date and time that the association was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The user identifier of the person that updated the association.</p>
    pub updated_by: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the queue in the association.</p>
    pub queue_id: ::std::string::String,
    /// <p>The unique identifier of the limit in the association.</p>
    pub limit_id: ::std::string::String,
    /// <p>The status of task scheduling in the queue-limit association.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - Association is active.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_COMPLETE_TASKS</code> - Association has stopped scheduling new tasks and is completing current tasks.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_CANCEL_TASKS</code> - Association has stopped scheduling new tasks and is canceling current tasks.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> - Association has been stopped.</p></li>
    /// </ul>
    pub status: crate::types::QueueLimitAssociationStatus,
}
impl QueueLimitAssociationSummary {
    /// <p>The Unix timestamp of the date and time that the association was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The user identifier of the person that created the association.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The Unix timestamp of the date and time that the association was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The user identifier of the person that updated the association.</p>
    pub fn updated_by(&self) -> ::std::option::Option<&str> {
        self.updated_by.as_deref()
    }
    /// <p>The unique identifier of the queue in the association.</p>
    pub fn queue_id(&self) -> &str {
        use std::ops::Deref;
        self.queue_id.deref()
    }
    /// <p>The unique identifier of the limit in the association.</p>
    pub fn limit_id(&self) -> &str {
        use std::ops::Deref;
        self.limit_id.deref()
    }
    /// <p>The status of task scheduling in the queue-limit association.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - Association is active.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_COMPLETE_TASKS</code> - Association has stopped scheduling new tasks and is completing current tasks.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_CANCEL_TASKS</code> - Association has stopped scheduling new tasks and is canceling current tasks.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> - Association has been stopped.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::QueueLimitAssociationStatus {
        &self.status
    }
}
impl QueueLimitAssociationSummary {
    /// Creates a new builder-style object to manufacture [`QueueLimitAssociationSummary`](crate::types::QueueLimitAssociationSummary).
    pub fn builder() -> crate::types::builders::QueueLimitAssociationSummaryBuilder {
        crate::types::builders::QueueLimitAssociationSummaryBuilder::default()
    }
}

/// A builder for [`QueueLimitAssociationSummary`](crate::types::QueueLimitAssociationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueueLimitAssociationSummaryBuilder {
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) limit_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::QueueLimitAssociationStatus>,
}
impl QueueLimitAssociationSummaryBuilder {
    /// <p>The Unix timestamp of the date and time that the association was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp of the date and time that the association was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp of the date and time that the association was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The user identifier of the person that created the association.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user identifier of the person that created the association.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user identifier of the person that created the association.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The Unix timestamp of the date and time that the association was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp of the date and time that the association was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The Unix timestamp of the date and time that the association was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The user identifier of the person that updated the association.</p>
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user identifier of the person that updated the association.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The user identifier of the person that updated the association.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    /// <p>The unique identifier of the queue in the association.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the queue in the association.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The unique identifier of the queue in the association.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The unique identifier of the limit in the association.</p>
    /// This field is required.
    pub fn limit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.limit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the limit in the association.</p>
    pub fn set_limit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.limit_id = input;
        self
    }
    /// <p>The unique identifier of the limit in the association.</p>
    pub fn get_limit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.limit_id
    }
    /// <p>The status of task scheduling in the queue-limit association.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - Association is active.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_COMPLETE_TASKS</code> - Association has stopped scheduling new tasks and is completing current tasks.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_CANCEL_TASKS</code> - Association has stopped scheduling new tasks and is canceling current tasks.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> - Association has been stopped.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::QueueLimitAssociationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of task scheduling in the queue-limit association.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - Association is active.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_COMPLETE_TASKS</code> - Association has stopped scheduling new tasks and is completing current tasks.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_CANCEL_TASKS</code> - Association has stopped scheduling new tasks and is canceling current tasks.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> - Association has been stopped.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::QueueLimitAssociationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of task scheduling in the queue-limit association.</p>
    /// <ul>
    /// <li>
    /// <p><code>ACTIVE</code> - Association is active.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_COMPLETE_TASKS</code> - Association has stopped scheduling new tasks and is completing current tasks.</p></li>
    /// <li>
    /// <p><code>STOP_LIMIT_USAGE_AND_CANCEL_TASKS</code> - Association has stopped scheduling new tasks and is canceling current tasks.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> - Association has been stopped.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::QueueLimitAssociationStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`QueueLimitAssociationSummary`](crate::types::QueueLimitAssociationSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`created_at`](crate::types::builders::QueueLimitAssociationSummaryBuilder::created_at)
    /// - [`created_by`](crate::types::builders::QueueLimitAssociationSummaryBuilder::created_by)
    /// - [`queue_id`](crate::types::builders::QueueLimitAssociationSummaryBuilder::queue_id)
    /// - [`limit_id`](crate::types::builders::QueueLimitAssociationSummaryBuilder::limit_id)
    /// - [`status`](crate::types::builders::QueueLimitAssociationSummaryBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::QueueLimitAssociationSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QueueLimitAssociationSummary {
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building QueueLimitAssociationSummary",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building QueueLimitAssociationSummary",
                )
            })?,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            queue_id: self.queue_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "queue_id",
                    "queue_id was not specified but it is required when building QueueLimitAssociationSummary",
                )
            })?,
            limit_id: self.limit_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "limit_id",
                    "limit_id was not specified but it is required when building QueueLimitAssociationSummary",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building QueueLimitAssociationSummary",
                )
            })?,
        })
    }
}
