// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a blocker for a sync event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SyncBlocker {
    /// <p>The ID for a specific sync blocker.</p>
    pub id: ::std::string::String,
    /// <p>The sync blocker type.</p>
    pub r#type: crate::types::BlockerType,
    /// <p>The status for a specific sync blocker.</p>
    pub status: crate::types::BlockerStatus,
    /// <p>The provided reason for a specific sync blocker.</p>
    pub created_reason: ::std::string::String,
    /// <p>The creation time for a specific sync blocker.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The contexts for a specific sync blocker.</p>
    pub contexts: ::std::option::Option<::std::vec::Vec<crate::types::SyncBlockerContext>>,
    /// <p>The resolved reason for a specific sync blocker.</p>
    pub resolved_reason: ::std::option::Option<::std::string::String>,
    /// <p>The time that a specific sync blocker was resolved.</p>
    pub resolved_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SyncBlocker {
    /// <p>The ID for a specific sync blocker.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The sync blocker type.</p>
    pub fn r#type(&self) -> &crate::types::BlockerType {
        &self.r#type
    }
    /// <p>The status for a specific sync blocker.</p>
    pub fn status(&self) -> &crate::types::BlockerStatus {
        &self.status
    }
    /// <p>The provided reason for a specific sync blocker.</p>
    pub fn created_reason(&self) -> &str {
        use std::ops::Deref;
        self.created_reason.deref()
    }
    /// <p>The creation time for a specific sync blocker.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The contexts for a specific sync blocker.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.contexts.is_none()`.
    pub fn contexts(&self) -> &[crate::types::SyncBlockerContext] {
        self.contexts.as_deref().unwrap_or_default()
    }
    /// <p>The resolved reason for a specific sync blocker.</p>
    pub fn resolved_reason(&self) -> ::std::option::Option<&str> {
        self.resolved_reason.as_deref()
    }
    /// <p>The time that a specific sync blocker was resolved.</p>
    pub fn resolved_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.resolved_at.as_ref()
    }
}
impl SyncBlocker {
    /// Creates a new builder-style object to manufacture [`SyncBlocker`](crate::types::SyncBlocker).
    pub fn builder() -> crate::types::builders::SyncBlockerBuilder {
        crate::types::builders::SyncBlockerBuilder::default()
    }
}

/// A builder for [`SyncBlocker`](crate::types::SyncBlocker).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SyncBlockerBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::BlockerType>,
    pub(crate) status: ::std::option::Option<crate::types::BlockerStatus>,
    pub(crate) created_reason: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) contexts: ::std::option::Option<::std::vec::Vec<crate::types::SyncBlockerContext>>,
    pub(crate) resolved_reason: ::std::option::Option<::std::string::String>,
    pub(crate) resolved_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SyncBlockerBuilder {
    /// <p>The ID for a specific sync blocker.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for a specific sync blocker.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID for a specific sync blocker.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The sync blocker type.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::BlockerType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sync blocker type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::BlockerType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The sync blocker type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::BlockerType> {
        &self.r#type
    }
    /// <p>The status for a specific sync blocker.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::BlockerStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status for a specific sync blocker.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::BlockerStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status for a specific sync blocker.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::BlockerStatus> {
        &self.status
    }
    /// <p>The provided reason for a specific sync blocker.</p>
    /// This field is required.
    pub fn created_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The provided reason for a specific sync blocker.</p>
    pub fn set_created_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_reason = input;
        self
    }
    /// <p>The provided reason for a specific sync blocker.</p>
    pub fn get_created_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_reason
    }
    /// <p>The creation time for a specific sync blocker.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation time for a specific sync blocker.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The creation time for a specific sync blocker.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// Appends an item to `contexts`.
    ///
    /// To override the contents of this collection use [`set_contexts`](Self::set_contexts).
    ///
    /// <p>The contexts for a specific sync blocker.</p>
    pub fn contexts(mut self, input: crate::types::SyncBlockerContext) -> Self {
        let mut v = self.contexts.unwrap_or_default();
        v.push(input);
        self.contexts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The contexts for a specific sync blocker.</p>
    pub fn set_contexts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SyncBlockerContext>>) -> Self {
        self.contexts = input;
        self
    }
    /// <p>The contexts for a specific sync blocker.</p>
    pub fn get_contexts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SyncBlockerContext>> {
        &self.contexts
    }
    /// <p>The resolved reason for a specific sync blocker.</p>
    pub fn resolved_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resolved_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resolved reason for a specific sync blocker.</p>
    pub fn set_resolved_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resolved_reason = input;
        self
    }
    /// <p>The resolved reason for a specific sync blocker.</p>
    pub fn get_resolved_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.resolved_reason
    }
    /// <p>The time that a specific sync blocker was resolved.</p>
    pub fn resolved_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.resolved_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that a specific sync blocker was resolved.</p>
    pub fn set_resolved_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.resolved_at = input;
        self
    }
    /// <p>The time that a specific sync blocker was resolved.</p>
    pub fn get_resolved_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.resolved_at
    }
    /// Consumes the builder and constructs a [`SyncBlocker`](crate::types::SyncBlocker).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::SyncBlockerBuilder::id)
    /// - [`r#type`](crate::types::builders::SyncBlockerBuilder::type)
    /// - [`status`](crate::types::builders::SyncBlockerBuilder::status)
    /// - [`created_reason`](crate::types::builders::SyncBlockerBuilder::created_reason)
    /// - [`created_at`](crate::types::builders::SyncBlockerBuilder::created_at)
    pub fn build(self) -> ::std::result::Result<crate::types::SyncBlocker, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SyncBlocker {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building SyncBlocker",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building SyncBlocker",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building SyncBlocker",
                )
            })?,
            created_reason: self.created_reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_reason",
                    "created_reason was not specified but it is required when building SyncBlocker",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building SyncBlocker",
                )
            })?,
            contexts: self.contexts,
            resolved_reason: self.resolved_reason,
            resolved_at: self.resolved_at,
        })
    }
}
