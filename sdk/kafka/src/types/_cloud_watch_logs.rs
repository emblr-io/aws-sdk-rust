// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLogs {
    #[allow(missing_docs)] // documentation missing in model
    pub enabled: ::std::option::Option<bool>,
    #[allow(missing_docs)] // documentation missing in model
    pub log_group: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogs {
    #[allow(missing_docs)] // documentation missing in model
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn log_group(&self) -> ::std::option::Option<&str> {
        self.log_group.as_deref()
    }
}
impl CloudWatchLogs {
    /// Creates a new builder-style object to manufacture [`CloudWatchLogs`](crate::types::CloudWatchLogs).
    pub fn builder() -> crate::types::builders::CloudWatchLogsBuilder {
        crate::types::builders::CloudWatchLogsBuilder::default()
    }
}

/// A builder for [`CloudWatchLogs`](crate::types::CloudWatchLogs).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchLogsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) log_group: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsBuilder {
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn log_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_log_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_log_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group
    }
    /// Consumes the builder and constructs a [`CloudWatchLogs`](crate::types::CloudWatchLogs).
    pub fn build(self) -> crate::types::CloudWatchLogs {
        crate::types::CloudWatchLogs {
            enabled: self.enabled,
            log_group: self.log_group,
        }
    }
}
