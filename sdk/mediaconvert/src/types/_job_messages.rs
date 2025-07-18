// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Provides messages from the service about jobs that you have already successfully submitted.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobMessages {
    /// List of messages that are informational only and don't indicate a problem with your job.
    pub info: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// List of messages that warn about conditions that might cause your job not to run or to fail.
    pub warning: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl JobMessages {
    /// List of messages that are informational only and don't indicate a problem with your job.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.info.is_none()`.
    pub fn info(&self) -> &[::std::string::String] {
        self.info.as_deref().unwrap_or_default()
    }
    /// List of messages that warn about conditions that might cause your job not to run or to fail.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.warning.is_none()`.
    pub fn warning(&self) -> &[::std::string::String] {
        self.warning.as_deref().unwrap_or_default()
    }
}
impl JobMessages {
    /// Creates a new builder-style object to manufacture [`JobMessages`](crate::types::JobMessages).
    pub fn builder() -> crate::types::builders::JobMessagesBuilder {
        crate::types::builders::JobMessagesBuilder::default()
    }
}

/// A builder for [`JobMessages`](crate::types::JobMessages).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobMessagesBuilder {
    pub(crate) info: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) warning: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl JobMessagesBuilder {
    /// Appends an item to `info`.
    ///
    /// To override the contents of this collection use [`set_info`](Self::set_info).
    ///
    /// List of messages that are informational only and don't indicate a problem with your job.
    pub fn info(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.info.unwrap_or_default();
        v.push(input.into());
        self.info = ::std::option::Option::Some(v);
        self
    }
    /// List of messages that are informational only and don't indicate a problem with your job.
    pub fn set_info(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.info = input;
        self
    }
    /// List of messages that are informational only and don't indicate a problem with your job.
    pub fn get_info(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.info
    }
    /// Appends an item to `warning`.
    ///
    /// To override the contents of this collection use [`set_warning`](Self::set_warning).
    ///
    /// List of messages that warn about conditions that might cause your job not to run or to fail.
    pub fn warning(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.warning.unwrap_or_default();
        v.push(input.into());
        self.warning = ::std::option::Option::Some(v);
        self
    }
    /// List of messages that warn about conditions that might cause your job not to run or to fail.
    pub fn set_warning(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.warning = input;
        self
    }
    /// List of messages that warn about conditions that might cause your job not to run or to fail.
    pub fn get_warning(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.warning
    }
    /// Consumes the builder and constructs a [`JobMessages`](crate::types::JobMessages).
    pub fn build(self) -> crate::types::JobMessages {
        crate::types::JobMessages {
            info: self.info,
            warning: self.warning,
        }
    }
}
