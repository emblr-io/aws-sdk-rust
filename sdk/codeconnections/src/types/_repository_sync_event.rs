// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a repository sync event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RepositorySyncEvent {
    /// <p>A description of a repository sync event.</p>
    pub event: ::std::string::String,
    /// <p>The ID for a repository sync event.</p>
    pub external_id: ::std::option::Option<::std::string::String>,
    /// <p>The time that a repository sync event occurred.</p>
    pub time: ::aws_smithy_types::DateTime,
    /// <p>The event type for a repository sync event.</p>
    pub r#type: ::std::string::String,
}
impl RepositorySyncEvent {
    /// <p>A description of a repository sync event.</p>
    pub fn event(&self) -> &str {
        use std::ops::Deref;
        self.event.deref()
    }
    /// <p>The ID for a repository sync event.</p>
    pub fn external_id(&self) -> ::std::option::Option<&str> {
        self.external_id.as_deref()
    }
    /// <p>The time that a repository sync event occurred.</p>
    pub fn time(&self) -> &::aws_smithy_types::DateTime {
        &self.time
    }
    /// <p>The event type for a repository sync event.</p>
    pub fn r#type(&self) -> &str {
        use std::ops::Deref;
        self.r#type.deref()
    }
}
impl RepositorySyncEvent {
    /// Creates a new builder-style object to manufacture [`RepositorySyncEvent`](crate::types::RepositorySyncEvent).
    pub fn builder() -> crate::types::builders::RepositorySyncEventBuilder {
        crate::types::builders::RepositorySyncEventBuilder::default()
    }
}

/// A builder for [`RepositorySyncEvent`](crate::types::RepositorySyncEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RepositorySyncEventBuilder {
    pub(crate) event: ::std::option::Option<::std::string::String>,
    pub(crate) external_id: ::std::option::Option<::std::string::String>,
    pub(crate) time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
}
impl RepositorySyncEventBuilder {
    /// <p>A description of a repository sync event.</p>
    /// This field is required.
    pub fn event(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of a repository sync event.</p>
    pub fn set_event(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event = input;
        self
    }
    /// <p>A description of a repository sync event.</p>
    pub fn get_event(&self) -> &::std::option::Option<::std::string::String> {
        &self.event
    }
    /// <p>The ID for a repository sync event.</p>
    pub fn external_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for a repository sync event.</p>
    pub fn set_external_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_id = input;
        self
    }
    /// <p>The ID for a repository sync event.</p>
    pub fn get_external_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_id
    }
    /// <p>The time that a repository sync event occurred.</p>
    /// This field is required.
    pub fn time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that a repository sync event occurred.</p>
    pub fn set_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.time = input;
        self
    }
    /// <p>The time that a repository sync event occurred.</p>
    pub fn get_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.time
    }
    /// <p>The event type for a repository sync event.</p>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The event type for a repository sync event.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The event type for a repository sync event.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`RepositorySyncEvent`](crate::types::RepositorySyncEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`event`](crate::types::builders::RepositorySyncEventBuilder::event)
    /// - [`time`](crate::types::builders::RepositorySyncEventBuilder::time)
    /// - [`r#type`](crate::types::builders::RepositorySyncEventBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::RepositorySyncEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RepositorySyncEvent {
            event: self.event.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event",
                    "event was not specified but it is required when building RepositorySyncEvent",
                )
            })?,
            external_id: self.external_id,
            time: self.time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "time",
                    "time was not specified but it is required when building RepositorySyncEvent",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building RepositorySyncEvent",
                )
            })?,
        })
    }
}
