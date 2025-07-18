// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the status of an export task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportTaskStatus {
    /// <p>The status code of the export task.</p>
    pub code: ::std::option::Option<crate::types::ExportTaskStatusCode>,
    /// <p>The status message related to the status code.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl ExportTaskStatus {
    /// <p>The status code of the export task.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::ExportTaskStatusCode> {
        self.code.as_ref()
    }
    /// <p>The status message related to the status code.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ExportTaskStatus {
    /// Creates a new builder-style object to manufacture [`ExportTaskStatus`](crate::types::ExportTaskStatus).
    pub fn builder() -> crate::types::builders::ExportTaskStatusBuilder {
        crate::types::builders::ExportTaskStatusBuilder::default()
    }
}

/// A builder for [`ExportTaskStatus`](crate::types::ExportTaskStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportTaskStatusBuilder {
    pub(crate) code: ::std::option::Option<crate::types::ExportTaskStatusCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl ExportTaskStatusBuilder {
    /// <p>The status code of the export task.</p>
    pub fn code(mut self, input: crate::types::ExportTaskStatusCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status code of the export task.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::ExportTaskStatusCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The status code of the export task.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::ExportTaskStatusCode> {
        &self.code
    }
    /// <p>The status message related to the status code.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message related to the status code.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The status message related to the status code.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`ExportTaskStatus`](crate::types::ExportTaskStatus).
    pub fn build(self) -> crate::types::ExportTaskStatus {
        crate::types::ExportTaskStatus {
            code: self.code,
            message: self.message,
        }
    }
}
