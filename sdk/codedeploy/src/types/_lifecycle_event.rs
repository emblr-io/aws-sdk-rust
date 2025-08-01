// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a deployment lifecycle event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LifecycleEvent {
    /// <p>The deployment lifecycle event name, such as <code>ApplicationStop</code>, <code>BeforeInstall</code>, <code>AfterInstall</code>, <code>ApplicationStart</code>, or <code>ValidateService</code>.</p>
    pub lifecycle_event_name: ::std::option::Option<::std::string::String>,
    /// <p>Diagnostic information about the deployment lifecycle event.</p>
    pub diagnostics: ::std::option::Option<crate::types::Diagnostics>,
    /// <p>A timestamp that indicates when the deployment lifecycle event started.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp that indicates when the deployment lifecycle event ended.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The deployment lifecycle event status:</p>
    /// <ul>
    /// <li>
    /// <p>Pending: The deployment lifecycle event is pending.</p></li>
    /// <li>
    /// <p>InProgress: The deployment lifecycle event is in progress.</p></li>
    /// <li>
    /// <p>Succeeded: The deployment lifecycle event ran successfully.</p></li>
    /// <li>
    /// <p>Failed: The deployment lifecycle event has failed.</p></li>
    /// <li>
    /// <p>Skipped: The deployment lifecycle event has been skipped.</p></li>
    /// <li>
    /// <p>Unknown: The deployment lifecycle event is unknown.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::LifecycleEventStatus>,
}
impl LifecycleEvent {
    /// <p>The deployment lifecycle event name, such as <code>ApplicationStop</code>, <code>BeforeInstall</code>, <code>AfterInstall</code>, <code>ApplicationStart</code>, or <code>ValidateService</code>.</p>
    pub fn lifecycle_event_name(&self) -> ::std::option::Option<&str> {
        self.lifecycle_event_name.as_deref()
    }
    /// <p>Diagnostic information about the deployment lifecycle event.</p>
    pub fn diagnostics(&self) -> ::std::option::Option<&crate::types::Diagnostics> {
        self.diagnostics.as_ref()
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event ended.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The deployment lifecycle event status:</p>
    /// <ul>
    /// <li>
    /// <p>Pending: The deployment lifecycle event is pending.</p></li>
    /// <li>
    /// <p>InProgress: The deployment lifecycle event is in progress.</p></li>
    /// <li>
    /// <p>Succeeded: The deployment lifecycle event ran successfully.</p></li>
    /// <li>
    /// <p>Failed: The deployment lifecycle event has failed.</p></li>
    /// <li>
    /// <p>Skipped: The deployment lifecycle event has been skipped.</p></li>
    /// <li>
    /// <p>Unknown: The deployment lifecycle event is unknown.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::LifecycleEventStatus> {
        self.status.as_ref()
    }
}
impl LifecycleEvent {
    /// Creates a new builder-style object to manufacture [`LifecycleEvent`](crate::types::LifecycleEvent).
    pub fn builder() -> crate::types::builders::LifecycleEventBuilder {
        crate::types::builders::LifecycleEventBuilder::default()
    }
}

/// A builder for [`LifecycleEvent`](crate::types::LifecycleEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LifecycleEventBuilder {
    pub(crate) lifecycle_event_name: ::std::option::Option<::std::string::String>,
    pub(crate) diagnostics: ::std::option::Option<crate::types::Diagnostics>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::LifecycleEventStatus>,
}
impl LifecycleEventBuilder {
    /// <p>The deployment lifecycle event name, such as <code>ApplicationStop</code>, <code>BeforeInstall</code>, <code>AfterInstall</code>, <code>ApplicationStart</code>, or <code>ValidateService</code>.</p>
    pub fn lifecycle_event_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_event_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The deployment lifecycle event name, such as <code>ApplicationStop</code>, <code>BeforeInstall</code>, <code>AfterInstall</code>, <code>ApplicationStart</code>, or <code>ValidateService</code>.</p>
    pub fn set_lifecycle_event_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_event_name = input;
        self
    }
    /// <p>The deployment lifecycle event name, such as <code>ApplicationStop</code>, <code>BeforeInstall</code>, <code>AfterInstall</code>, <code>ApplicationStart</code>, or <code>ValidateService</code>.</p>
    pub fn get_lifecycle_event_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_event_name
    }
    /// <p>Diagnostic information about the deployment lifecycle event.</p>
    pub fn diagnostics(mut self, input: crate::types::Diagnostics) -> Self {
        self.diagnostics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Diagnostic information about the deployment lifecycle event.</p>
    pub fn set_diagnostics(mut self, input: ::std::option::Option<crate::types::Diagnostics>) -> Self {
        self.diagnostics = input;
        self
    }
    /// <p>Diagnostic information about the deployment lifecycle event.</p>
    pub fn get_diagnostics(&self) -> &::std::option::Option<crate::types::Diagnostics> {
        &self.diagnostics
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event started.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event ended.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event ended.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>A timestamp that indicates when the deployment lifecycle event ended.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The deployment lifecycle event status:</p>
    /// <ul>
    /// <li>
    /// <p>Pending: The deployment lifecycle event is pending.</p></li>
    /// <li>
    /// <p>InProgress: The deployment lifecycle event is in progress.</p></li>
    /// <li>
    /// <p>Succeeded: The deployment lifecycle event ran successfully.</p></li>
    /// <li>
    /// <p>Failed: The deployment lifecycle event has failed.</p></li>
    /// <li>
    /// <p>Skipped: The deployment lifecycle event has been skipped.</p></li>
    /// <li>
    /// <p>Unknown: The deployment lifecycle event is unknown.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::LifecycleEventStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deployment lifecycle event status:</p>
    /// <ul>
    /// <li>
    /// <p>Pending: The deployment lifecycle event is pending.</p></li>
    /// <li>
    /// <p>InProgress: The deployment lifecycle event is in progress.</p></li>
    /// <li>
    /// <p>Succeeded: The deployment lifecycle event ran successfully.</p></li>
    /// <li>
    /// <p>Failed: The deployment lifecycle event has failed.</p></li>
    /// <li>
    /// <p>Skipped: The deployment lifecycle event has been skipped.</p></li>
    /// <li>
    /// <p>Unknown: The deployment lifecycle event is unknown.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LifecycleEventStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The deployment lifecycle event status:</p>
    /// <ul>
    /// <li>
    /// <p>Pending: The deployment lifecycle event is pending.</p></li>
    /// <li>
    /// <p>InProgress: The deployment lifecycle event is in progress.</p></li>
    /// <li>
    /// <p>Succeeded: The deployment lifecycle event ran successfully.</p></li>
    /// <li>
    /// <p>Failed: The deployment lifecycle event has failed.</p></li>
    /// <li>
    /// <p>Skipped: The deployment lifecycle event has been skipped.</p></li>
    /// <li>
    /// <p>Unknown: The deployment lifecycle event is unknown.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LifecycleEventStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`LifecycleEvent`](crate::types::LifecycleEvent).
    pub fn build(self) -> crate::types::LifecycleEvent {
        crate::types::LifecycleEvent {
            lifecycle_event_name: self.lifecycle_event_name,
            diagnostics: self.diagnostics,
            start_time: self.start_time,
            end_time: self.end_time,
            status: self.status,
        }
    }
}
