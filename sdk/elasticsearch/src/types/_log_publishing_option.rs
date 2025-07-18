// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Log Publishing option that is set for given domain. <br><br>
/// Attributes and their details:</p>
/// <ul>
/// <li>CloudWatchLogsLogGroupArn: ARN of the Cloudwatch log group to which log needs to be published.</li>
/// <li>Enabled: Whether the log publishing for given log type is enabled or not</li>
/// </ul>
/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogPublishingOption {
    /// <p>ARN of the Cloudwatch log group to which log needs to be published.</p>
    pub cloud_watch_logs_log_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether given log publishing option is enabled or not.</p>
    pub enabled: ::std::option::Option<bool>,
}
impl LogPublishingOption {
    /// <p>ARN of the Cloudwatch log group to which log needs to be published.</p>
    pub fn cloud_watch_logs_log_group_arn(&self) -> ::std::option::Option<&str> {
        self.cloud_watch_logs_log_group_arn.as_deref()
    }
    /// <p>Specifies whether given log publishing option is enabled or not.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
}
impl LogPublishingOption {
    /// Creates a new builder-style object to manufacture [`LogPublishingOption`](crate::types::LogPublishingOption).
    pub fn builder() -> crate::types::builders::LogPublishingOptionBuilder {
        crate::types::builders::LogPublishingOptionBuilder::default()
    }
}

/// A builder for [`LogPublishingOption`](crate::types::LogPublishingOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogPublishingOptionBuilder {
    pub(crate) cloud_watch_logs_log_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl LogPublishingOptionBuilder {
    /// <p>ARN of the Cloudwatch log group to which log needs to be published.</p>
    pub fn cloud_watch_logs_log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_watch_logs_log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the Cloudwatch log group to which log needs to be published.</p>
    pub fn set_cloud_watch_logs_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_watch_logs_log_group_arn = input;
        self
    }
    /// <p>ARN of the Cloudwatch log group to which log needs to be published.</p>
    pub fn get_cloud_watch_logs_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_watch_logs_log_group_arn
    }
    /// <p>Specifies whether given log publishing option is enabled or not.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether given log publishing option is enabled or not.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Specifies whether given log publishing option is enabled or not.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`LogPublishingOption`](crate::types::LogPublishingOption).
    pub fn build(self) -> crate::types::LogPublishingOption {
        crate::types::LogPublishingOption {
            cloud_watch_logs_log_group_arn: self.cloud_watch_logs_log_group_arn,
            enabled: self.enabled,
        }
    }
}
