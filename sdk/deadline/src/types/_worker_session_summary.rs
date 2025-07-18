// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summarizes the session for a particular worker.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkerSessionSummary {
    /// <p>The session ID for the session action.</p>
    pub session_id: ::std::string::String,
    /// <p>The queue ID for the queue associated to the worker.</p>
    pub queue_id: ::std::string::String,
    /// <p>The job ID for the job associated with the worker's session.</p>
    pub job_id: ::std::string::String,
    /// <p>The date and time the resource started running.</p>
    pub started_at: ::aws_smithy_types::DateTime,
    /// <p>The life cycle status for the worker's session.</p>
    pub lifecycle_status: crate::types::SessionLifecycleStatus,
    /// <p>The date and time the resource ended running.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The life cycle status</p>
    pub target_lifecycle_status: ::std::option::Option<crate::types::SessionLifecycleTargetStatus>,
}
impl WorkerSessionSummary {
    /// <p>The session ID for the session action.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
    /// <p>The queue ID for the queue associated to the worker.</p>
    pub fn queue_id(&self) -> &str {
        use std::ops::Deref;
        self.queue_id.deref()
    }
    /// <p>The job ID for the job associated with the worker's session.</p>
    pub fn job_id(&self) -> &str {
        use std::ops::Deref;
        self.job_id.deref()
    }
    /// <p>The date and time the resource started running.</p>
    pub fn started_at(&self) -> &::aws_smithy_types::DateTime {
        &self.started_at
    }
    /// <p>The life cycle status for the worker's session.</p>
    pub fn lifecycle_status(&self) -> &crate::types::SessionLifecycleStatus {
        &self.lifecycle_status
    }
    /// <p>The date and time the resource ended running.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>The life cycle status</p>
    pub fn target_lifecycle_status(&self) -> ::std::option::Option<&crate::types::SessionLifecycleTargetStatus> {
        self.target_lifecycle_status.as_ref()
    }
}
impl WorkerSessionSummary {
    /// Creates a new builder-style object to manufacture [`WorkerSessionSummary`](crate::types::WorkerSessionSummary).
    pub fn builder() -> crate::types::builders::WorkerSessionSummaryBuilder {
        crate::types::builders::WorkerSessionSummaryBuilder::default()
    }
}

/// A builder for [`WorkerSessionSummary`](crate::types::WorkerSessionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkerSessionSummaryBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) lifecycle_status: ::std::option::Option<crate::types::SessionLifecycleStatus>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) target_lifecycle_status: ::std::option::Option<crate::types::SessionLifecycleTargetStatus>,
}
impl WorkerSessionSummaryBuilder {
    /// <p>The session ID for the session action.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The session ID for the session action.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The session ID for the session action.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The queue ID for the queue associated to the worker.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID for the queue associated to the worker.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID for the queue associated to the worker.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The job ID for the job associated with the worker's session.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job ID for the job associated with the worker's session.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The job ID for the job associated with the worker's session.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The date and time the resource started running.</p>
    /// This field is required.
    pub fn started_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the resource started running.</p>
    pub fn set_started_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_at = input;
        self
    }
    /// <p>The date and time the resource started running.</p>
    pub fn get_started_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_at
    }
    /// <p>The life cycle status for the worker's session.</p>
    /// This field is required.
    pub fn lifecycle_status(mut self, input: crate::types::SessionLifecycleStatus) -> Self {
        self.lifecycle_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The life cycle status for the worker's session.</p>
    pub fn set_lifecycle_status(mut self, input: ::std::option::Option<crate::types::SessionLifecycleStatus>) -> Self {
        self.lifecycle_status = input;
        self
    }
    /// <p>The life cycle status for the worker's session.</p>
    pub fn get_lifecycle_status(&self) -> &::std::option::Option<crate::types::SessionLifecycleStatus> {
        &self.lifecycle_status
    }
    /// <p>The date and time the resource ended running.</p>
    pub fn ended_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.ended_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the resource ended running.</p>
    pub fn set_ended_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.ended_at = input;
        self
    }
    /// <p>The date and time the resource ended running.</p>
    pub fn get_ended_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.ended_at
    }
    /// <p>The life cycle status</p>
    pub fn target_lifecycle_status(mut self, input: crate::types::SessionLifecycleTargetStatus) -> Self {
        self.target_lifecycle_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The life cycle status</p>
    pub fn set_target_lifecycle_status(mut self, input: ::std::option::Option<crate::types::SessionLifecycleTargetStatus>) -> Self {
        self.target_lifecycle_status = input;
        self
    }
    /// <p>The life cycle status</p>
    pub fn get_target_lifecycle_status(&self) -> &::std::option::Option<crate::types::SessionLifecycleTargetStatus> {
        &self.target_lifecycle_status
    }
    /// Consumes the builder and constructs a [`WorkerSessionSummary`](crate::types::WorkerSessionSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::types::builders::WorkerSessionSummaryBuilder::session_id)
    /// - [`queue_id`](crate::types::builders::WorkerSessionSummaryBuilder::queue_id)
    /// - [`job_id`](crate::types::builders::WorkerSessionSummaryBuilder::job_id)
    /// - [`started_at`](crate::types::builders::WorkerSessionSummaryBuilder::started_at)
    /// - [`lifecycle_status`](crate::types::builders::WorkerSessionSummaryBuilder::lifecycle_status)
    pub fn build(self) -> ::std::result::Result<crate::types::WorkerSessionSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WorkerSessionSummary {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building WorkerSessionSummary",
                )
            })?,
            queue_id: self.queue_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "queue_id",
                    "queue_id was not specified but it is required when building WorkerSessionSummary",
                )
            })?,
            job_id: self.job_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_id",
                    "job_id was not specified but it is required when building WorkerSessionSummary",
                )
            })?,
            started_at: self.started_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "started_at",
                    "started_at was not specified but it is required when building WorkerSessionSummary",
                )
            })?,
            lifecycle_status: self.lifecycle_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "lifecycle_status",
                    "lifecycle_status was not specified but it is required when building WorkerSessionSummary",
                )
            })?,
            ended_at: self.ended_at,
            target_lifecycle_status: self.target_lifecycle_status,
        })
    }
}
