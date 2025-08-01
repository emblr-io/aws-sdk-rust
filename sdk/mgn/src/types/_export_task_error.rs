// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Export task error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportTaskError {
    /// <p>Export task error datetime.</p>
    pub error_date_time: ::std::option::Option<::std::string::String>,
    /// <p>Export task error data.</p>
    pub error_data: ::std::option::Option<crate::types::ExportErrorData>,
}
impl ExportTaskError {
    /// <p>Export task error datetime.</p>
    pub fn error_date_time(&self) -> ::std::option::Option<&str> {
        self.error_date_time.as_deref()
    }
    /// <p>Export task error data.</p>
    pub fn error_data(&self) -> ::std::option::Option<&crate::types::ExportErrorData> {
        self.error_data.as_ref()
    }
}
impl ExportTaskError {
    /// Creates a new builder-style object to manufacture [`ExportTaskError`](crate::types::ExportTaskError).
    pub fn builder() -> crate::types::builders::ExportTaskErrorBuilder {
        crate::types::builders::ExportTaskErrorBuilder::default()
    }
}

/// A builder for [`ExportTaskError`](crate::types::ExportTaskError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportTaskErrorBuilder {
    pub(crate) error_date_time: ::std::option::Option<::std::string::String>,
    pub(crate) error_data: ::std::option::Option<crate::types::ExportErrorData>,
}
impl ExportTaskErrorBuilder {
    /// <p>Export task error datetime.</p>
    pub fn error_date_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_date_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Export task error datetime.</p>
    pub fn set_error_date_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_date_time = input;
        self
    }
    /// <p>Export task error datetime.</p>
    pub fn get_error_date_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_date_time
    }
    /// <p>Export task error data.</p>
    pub fn error_data(mut self, input: crate::types::ExportErrorData) -> Self {
        self.error_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Export task error data.</p>
    pub fn set_error_data(mut self, input: ::std::option::Option<crate::types::ExportErrorData>) -> Self {
        self.error_data = input;
        self
    }
    /// <p>Export task error data.</p>
    pub fn get_error_data(&self) -> &::std::option::Option<crate::types::ExportErrorData> {
        &self.error_data
    }
    /// Consumes the builder and constructs a [`ExportTaskError`](crate::types::ExportTaskError).
    pub fn build(self) -> crate::types::ExportTaskError {
        crate::types::ExportTaskError {
            error_date_time: self.error_date_time,
            error_data: self.error_data,
        }
    }
}
