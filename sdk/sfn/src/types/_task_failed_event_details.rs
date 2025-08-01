// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about a task failure event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TaskFailedEventDetails {
    /// <p>The service name of the resource in a task state.</p>
    pub resource_type: ::std::string::String,
    /// <p>The action of the resource called by a task state.</p>
    pub resource: ::std::string::String,
    /// <p>The error code of the failure.</p>
    pub error: ::std::option::Option<::std::string::String>,
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub cause: ::std::option::Option<::std::string::String>,
}
impl TaskFailedEventDetails {
    /// <p>The service name of the resource in a task state.</p>
    pub fn resource_type(&self) -> &str {
        use std::ops::Deref;
        self.resource_type.deref()
    }
    /// <p>The action of the resource called by a task state.</p>
    pub fn resource(&self) -> &str {
        use std::ops::Deref;
        self.resource.deref()
    }
    /// <p>The error code of the failure.</p>
    pub fn error(&self) -> ::std::option::Option<&str> {
        self.error.as_deref()
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn cause(&self) -> ::std::option::Option<&str> {
        self.cause.as_deref()
    }
}
impl ::std::fmt::Debug for TaskFailedEventDetails {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TaskFailedEventDetails");
        formatter.field("resource_type", &self.resource_type);
        formatter.field("resource", &self.resource);
        formatter.field("error", &"*** Sensitive Data Redacted ***");
        formatter.field("cause", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TaskFailedEventDetails {
    /// Creates a new builder-style object to manufacture [`TaskFailedEventDetails`](crate::types::TaskFailedEventDetails).
    pub fn builder() -> crate::types::builders::TaskFailedEventDetailsBuilder {
        crate::types::builders::TaskFailedEventDetailsBuilder::default()
    }
}

/// A builder for [`TaskFailedEventDetails`](crate::types::TaskFailedEventDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TaskFailedEventDetailsBuilder {
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) resource: ::std::option::Option<::std::string::String>,
    pub(crate) error: ::std::option::Option<::std::string::String>,
    pub(crate) cause: ::std::option::Option<::std::string::String>,
}
impl TaskFailedEventDetailsBuilder {
    /// <p>The service name of the resource in a task state.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service name of the resource in a task state.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The service name of the resource in a task state.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>The action of the resource called by a task state.</p>
    /// This field is required.
    pub fn resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The action of the resource called by a task state.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The action of the resource called by a task state.</p>
    pub fn get_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource
    }
    /// <p>The error code of the failure.</p>
    pub fn error(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code of the failure.</p>
    pub fn set_error(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error = input;
        self
    }
    /// <p>The error code of the failure.</p>
    pub fn get_error(&self) -> &::std::option::Option<::std::string::String> {
        &self.error
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn cause(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cause = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn set_cause(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cause = input;
        self
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn get_cause(&self) -> &::std::option::Option<::std::string::String> {
        &self.cause
    }
    /// Consumes the builder and constructs a [`TaskFailedEventDetails`](crate::types::TaskFailedEventDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_type`](crate::types::builders::TaskFailedEventDetailsBuilder::resource_type)
    /// - [`resource`](crate::types::builders::TaskFailedEventDetailsBuilder::resource)
    pub fn build(self) -> ::std::result::Result<crate::types::TaskFailedEventDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TaskFailedEventDetails {
            resource_type: self.resource_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_type",
                    "resource_type was not specified but it is required when building TaskFailedEventDetails",
                )
            })?,
            resource: self.resource.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource",
                    "resource was not specified but it is required when building TaskFailedEventDetails",
                )
            })?,
            error: self.error,
            cause: self.cause,
        })
    }
}
impl ::std::fmt::Debug for TaskFailedEventDetailsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TaskFailedEventDetailsBuilder");
        formatter.field("resource_type", &self.resource_type);
        formatter.field("resource", &self.resource);
        formatter.field("error", &"*** Sensitive Data Redacted ***");
        formatter.field("cause", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
