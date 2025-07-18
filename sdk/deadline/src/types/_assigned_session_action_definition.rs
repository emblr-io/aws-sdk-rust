// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The definition of the assigned session action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum AssignedSessionActionDefinition {
    /// <p>The environment a session starts on.</p>
    EnvEnter(crate::types::AssignedEnvironmentEnterSessionActionDefinition),
    /// <p>The environment a session exits from.</p>
    EnvExit(crate::types::AssignedEnvironmentExitSessionActionDefinition),
    /// <p>The job attachment to sync with an assigned session action.</p>
    SyncInputJobAttachments(crate::types::AssignedSyncInputJobAttachmentsSessionActionDefinition),
    /// <p>The task run.</p>
    TaskRun(crate::types::AssignedTaskRunSessionActionDefinition),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl AssignedSessionActionDefinition {
    /// Tries to convert the enum instance into [`EnvEnter`](crate::types::AssignedSessionActionDefinition::EnvEnter), extracting the inner [`AssignedEnvironmentEnterSessionActionDefinition`](crate::types::AssignedEnvironmentEnterSessionActionDefinition).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_env_enter(&self) -> ::std::result::Result<&crate::types::AssignedEnvironmentEnterSessionActionDefinition, &Self> {
        if let AssignedSessionActionDefinition::EnvEnter(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`EnvEnter`](crate::types::AssignedSessionActionDefinition::EnvEnter).
    pub fn is_env_enter(&self) -> bool {
        self.as_env_enter().is_ok()
    }
    /// Tries to convert the enum instance into [`EnvExit`](crate::types::AssignedSessionActionDefinition::EnvExit), extracting the inner [`AssignedEnvironmentExitSessionActionDefinition`](crate::types::AssignedEnvironmentExitSessionActionDefinition).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_env_exit(&self) -> ::std::result::Result<&crate::types::AssignedEnvironmentExitSessionActionDefinition, &Self> {
        if let AssignedSessionActionDefinition::EnvExit(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`EnvExit`](crate::types::AssignedSessionActionDefinition::EnvExit).
    pub fn is_env_exit(&self) -> bool {
        self.as_env_exit().is_ok()
    }
    /// Tries to convert the enum instance into [`SyncInputJobAttachments`](crate::types::AssignedSessionActionDefinition::SyncInputJobAttachments), extracting the inner [`AssignedSyncInputJobAttachmentsSessionActionDefinition`](crate::types::AssignedSyncInputJobAttachmentsSessionActionDefinition).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_sync_input_job_attachments(
        &self,
    ) -> ::std::result::Result<&crate::types::AssignedSyncInputJobAttachmentsSessionActionDefinition, &Self> {
        if let AssignedSessionActionDefinition::SyncInputJobAttachments(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`SyncInputJobAttachments`](crate::types::AssignedSessionActionDefinition::SyncInputJobAttachments).
    pub fn is_sync_input_job_attachments(&self) -> bool {
        self.as_sync_input_job_attachments().is_ok()
    }
    /// Tries to convert the enum instance into [`TaskRun`](crate::types::AssignedSessionActionDefinition::TaskRun), extracting the inner [`AssignedTaskRunSessionActionDefinition`](crate::types::AssignedTaskRunSessionActionDefinition).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_task_run(&self) -> ::std::result::Result<&crate::types::AssignedTaskRunSessionActionDefinition, &Self> {
        if let AssignedSessionActionDefinition::TaskRun(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`TaskRun`](crate::types::AssignedSessionActionDefinition::TaskRun).
    pub fn is_task_run(&self) -> bool {
        self.as_task_run().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
