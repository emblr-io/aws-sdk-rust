// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for delivering connector logs to Amazon CloudWatch Logs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLogsLogDelivery {
    /// <p>Whether log delivery to Amazon CloudWatch Logs is enabled.</p>
    pub enabled: bool,
    /// <p>The name of the CloudWatch log group that is the destination for log delivery.</p>
    pub log_group: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsLogDelivery {
    /// <p>Whether log delivery to Amazon CloudWatch Logs is enabled.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// <p>The name of the CloudWatch log group that is the destination for log delivery.</p>
    pub fn log_group(&self) -> ::std::option::Option<&str> {
        self.log_group.as_deref()
    }
}
impl CloudWatchLogsLogDelivery {
    /// Creates a new builder-style object to manufacture [`CloudWatchLogsLogDelivery`](crate::types::CloudWatchLogsLogDelivery).
    pub fn builder() -> crate::types::builders::CloudWatchLogsLogDeliveryBuilder {
        crate::types::builders::CloudWatchLogsLogDeliveryBuilder::default()
    }
}

/// A builder for [`CloudWatchLogsLogDelivery`](crate::types::CloudWatchLogsLogDelivery).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchLogsLogDeliveryBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) log_group: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsLogDeliveryBuilder {
    /// <p>Whether log delivery to Amazon CloudWatch Logs is enabled.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether log delivery to Amazon CloudWatch Logs is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Whether log delivery to Amazon CloudWatch Logs is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The name of the CloudWatch log group that is the destination for log delivery.</p>
    pub fn log_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudWatch log group that is the destination for log delivery.</p>
    pub fn set_log_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group = input;
        self
    }
    /// <p>The name of the CloudWatch log group that is the destination for log delivery.</p>
    pub fn get_log_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group
    }
    /// Consumes the builder and constructs a [`CloudWatchLogsLogDelivery`](crate::types::CloudWatchLogsLogDelivery).
    pub fn build(self) -> crate::types::CloudWatchLogsLogDelivery {
        crate::types::CloudWatchLogsLogDelivery {
            enabled: self.enabled.unwrap_or_default(),
            log_group: self.log_group,
        }
    }
}
