// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The updated session action information as it relates to completion and progress of the session.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdatedSessionActionInfo {
    /// <p>The status of the session upon completion.</p>
    pub completed_status: ::std::option::Option<crate::types::CompletedStatus>,
    /// <p>The process exit code. The default Deadline Cloud worker agent converts unsigned 32-bit exit codes to signed 32-bit exit codes.</p>
    pub process_exit_code: ::std::option::Option<i32>,
    /// <p>A message to indicate the progress of the updated session action.</p>
    pub progress_message: ::std::option::Option<::std::string::String>,
    /// <p>The date and time the resource started running.</p>
    pub started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time the resource ended running.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The updated time.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The percentage completed.</p>
    pub progress_percent: ::std::option::Option<f32>,
    /// <p>A list of output manifest properties reported by the worker agent, with each entry corresponding to a manifest property in the job.</p>
    pub manifests: ::std::option::Option<::std::vec::Vec<crate::types::TaskRunManifestPropertiesRequest>>,
}
impl UpdatedSessionActionInfo {
    /// <p>The status of the session upon completion.</p>
    pub fn completed_status(&self) -> ::std::option::Option<&crate::types::CompletedStatus> {
        self.completed_status.as_ref()
    }
    /// <p>The process exit code. The default Deadline Cloud worker agent converts unsigned 32-bit exit codes to signed 32-bit exit codes.</p>
    pub fn process_exit_code(&self) -> ::std::option::Option<i32> {
        self.process_exit_code
    }
    /// <p>A message to indicate the progress of the updated session action.</p>
    pub fn progress_message(&self) -> ::std::option::Option<&str> {
        self.progress_message.as_deref()
    }
    /// <p>The date and time the resource started running.</p>
    pub fn started_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.started_at.as_ref()
    }
    /// <p>The date and time the resource ended running.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>The updated time.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The percentage completed.</p>
    pub fn progress_percent(&self) -> ::std::option::Option<f32> {
        self.progress_percent
    }
    /// <p>A list of output manifest properties reported by the worker agent, with each entry corresponding to a manifest property in the job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.manifests.is_none()`.
    pub fn manifests(&self) -> &[crate::types::TaskRunManifestPropertiesRequest] {
        self.manifests.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for UpdatedSessionActionInfo {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatedSessionActionInfo");
        formatter.field("completed_status", &self.completed_status);
        formatter.field("process_exit_code", &self.process_exit_code);
        formatter.field("progress_message", &"*** Sensitive Data Redacted ***");
        formatter.field("started_at", &self.started_at);
        formatter.field("ended_at", &self.ended_at);
        formatter.field("updated_at", &self.updated_at);
        formatter.field("progress_percent", &self.progress_percent);
        formatter.field("manifests", &self.manifests);
        formatter.finish()
    }
}
impl UpdatedSessionActionInfo {
    /// Creates a new builder-style object to manufacture [`UpdatedSessionActionInfo`](crate::types::UpdatedSessionActionInfo).
    pub fn builder() -> crate::types::builders::UpdatedSessionActionInfoBuilder {
        crate::types::builders::UpdatedSessionActionInfoBuilder::default()
    }
}

/// A builder for [`UpdatedSessionActionInfo`](crate::types::UpdatedSessionActionInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdatedSessionActionInfoBuilder {
    pub(crate) completed_status: ::std::option::Option<crate::types::CompletedStatus>,
    pub(crate) process_exit_code: ::std::option::Option<i32>,
    pub(crate) progress_message: ::std::option::Option<::std::string::String>,
    pub(crate) started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) progress_percent: ::std::option::Option<f32>,
    pub(crate) manifests: ::std::option::Option<::std::vec::Vec<crate::types::TaskRunManifestPropertiesRequest>>,
}
impl UpdatedSessionActionInfoBuilder {
    /// <p>The status of the session upon completion.</p>
    pub fn completed_status(mut self, input: crate::types::CompletedStatus) -> Self {
        self.completed_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the session upon completion.</p>
    pub fn set_completed_status(mut self, input: ::std::option::Option<crate::types::CompletedStatus>) -> Self {
        self.completed_status = input;
        self
    }
    /// <p>The status of the session upon completion.</p>
    pub fn get_completed_status(&self) -> &::std::option::Option<crate::types::CompletedStatus> {
        &self.completed_status
    }
    /// <p>The process exit code. The default Deadline Cloud worker agent converts unsigned 32-bit exit codes to signed 32-bit exit codes.</p>
    pub fn process_exit_code(mut self, input: i32) -> Self {
        self.process_exit_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The process exit code. The default Deadline Cloud worker agent converts unsigned 32-bit exit codes to signed 32-bit exit codes.</p>
    pub fn set_process_exit_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.process_exit_code = input;
        self
    }
    /// <p>The process exit code. The default Deadline Cloud worker agent converts unsigned 32-bit exit codes to signed 32-bit exit codes.</p>
    pub fn get_process_exit_code(&self) -> &::std::option::Option<i32> {
        &self.process_exit_code
    }
    /// <p>A message to indicate the progress of the updated session action.</p>
    pub fn progress_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.progress_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message to indicate the progress of the updated session action.</p>
    pub fn set_progress_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.progress_message = input;
        self
    }
    /// <p>A message to indicate the progress of the updated session action.</p>
    pub fn get_progress_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.progress_message
    }
    /// <p>The date and time the resource started running.</p>
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
    /// <p>The updated time.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated time.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The updated time.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The percentage completed.</p>
    pub fn progress_percent(mut self, input: f32) -> Self {
        self.progress_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage completed.</p>
    pub fn set_progress_percent(mut self, input: ::std::option::Option<f32>) -> Self {
        self.progress_percent = input;
        self
    }
    /// <p>The percentage completed.</p>
    pub fn get_progress_percent(&self) -> &::std::option::Option<f32> {
        &self.progress_percent
    }
    /// Appends an item to `manifests`.
    ///
    /// To override the contents of this collection use [`set_manifests`](Self::set_manifests).
    ///
    /// <p>A list of output manifest properties reported by the worker agent, with each entry corresponding to a manifest property in the job.</p>
    pub fn manifests(mut self, input: crate::types::TaskRunManifestPropertiesRequest) -> Self {
        let mut v = self.manifests.unwrap_or_default();
        v.push(input);
        self.manifests = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of output manifest properties reported by the worker agent, with each entry corresponding to a manifest property in the job.</p>
    pub fn set_manifests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TaskRunManifestPropertiesRequest>>) -> Self {
        self.manifests = input;
        self
    }
    /// <p>A list of output manifest properties reported by the worker agent, with each entry corresponding to a manifest property in the job.</p>
    pub fn get_manifests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TaskRunManifestPropertiesRequest>> {
        &self.manifests
    }
    /// Consumes the builder and constructs a [`UpdatedSessionActionInfo`](crate::types::UpdatedSessionActionInfo).
    pub fn build(self) -> crate::types::UpdatedSessionActionInfo {
        crate::types::UpdatedSessionActionInfo {
            completed_status: self.completed_status,
            process_exit_code: self.process_exit_code,
            progress_message: self.progress_message,
            started_at: self.started_at,
            ended_at: self.ended_at,
            updated_at: self.updated_at,
            progress_percent: self.progress_percent,
            manifests: self.manifests,
        }
    }
}
impl ::std::fmt::Debug for UpdatedSessionActionInfoBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatedSessionActionInfoBuilder");
        formatter.field("completed_status", &self.completed_status);
        formatter.field("process_exit_code", &self.process_exit_code);
        formatter.field("progress_message", &"*** Sensitive Data Redacted ***");
        formatter.field("started_at", &self.started_at);
        formatter.field("ended_at", &self.ended_at);
        formatter.field("updated_at", &self.updated_at);
        formatter.field("progress_percent", &self.progress_percent);
        formatter.field("manifests", &self.manifests);
        formatter.finish()
    }
}
