// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The job attachment in a session action to sync.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SyncInputJobAttachmentsSessionActionDefinition {
    /// <p>The step ID for the step in the job attachment.</p>
    pub step_id: ::std::option::Option<::std::string::String>,
}
impl SyncInputJobAttachmentsSessionActionDefinition {
    /// <p>The step ID for the step in the job attachment.</p>
    pub fn step_id(&self) -> ::std::option::Option<&str> {
        self.step_id.as_deref()
    }
}
impl SyncInputJobAttachmentsSessionActionDefinition {
    /// Creates a new builder-style object to manufacture [`SyncInputJobAttachmentsSessionActionDefinition`](crate::types::SyncInputJobAttachmentsSessionActionDefinition).
    pub fn builder() -> crate::types::builders::SyncInputJobAttachmentsSessionActionDefinitionBuilder {
        crate::types::builders::SyncInputJobAttachmentsSessionActionDefinitionBuilder::default()
    }
}

/// A builder for [`SyncInputJobAttachmentsSessionActionDefinition`](crate::types::SyncInputJobAttachmentsSessionActionDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SyncInputJobAttachmentsSessionActionDefinitionBuilder {
    pub(crate) step_id: ::std::option::Option<::std::string::String>,
}
impl SyncInputJobAttachmentsSessionActionDefinitionBuilder {
    /// <p>The step ID for the step in the job attachment.</p>
    pub fn step_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The step ID for the step in the job attachment.</p>
    pub fn set_step_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_id = input;
        self
    }
    /// <p>The step ID for the step in the job attachment.</p>
    pub fn get_step_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_id
    }
    /// Consumes the builder and constructs a [`SyncInputJobAttachmentsSessionActionDefinition`](crate::types::SyncInputJobAttachmentsSessionActionDefinition).
    pub fn build(self) -> crate::types::SyncInputJobAttachmentsSessionActionDefinition {
        crate::types::SyncInputJobAttachmentsSessionActionDefinition { step_id: self.step_id }
    }
}
