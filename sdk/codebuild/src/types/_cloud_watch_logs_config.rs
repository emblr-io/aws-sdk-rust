// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about CloudWatch Logs for a build project.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLogsConfig {
    /// <p>The current status of the logs in CloudWatch Logs for a build project. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code>: CloudWatch Logs are enabled for this build project.</p></li>
    /// <li>
    /// <p><code>DISABLED</code>: CloudWatch Logs are not enabled for this build project.</p></li>
    /// </ul>
    pub status: crate::types::LogsConfigStatusType,
    /// <p>The group name of the logs in CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
    /// <p>The prefix of the stream name of the CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsConfig {
    /// <p>The current status of the logs in CloudWatch Logs for a build project. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code>: CloudWatch Logs are enabled for this build project.</p></li>
    /// <li>
    /// <p><code>DISABLED</code>: CloudWatch Logs are not enabled for this build project.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::LogsConfigStatusType {
        &self.status
    }
    /// <p>The group name of the logs in CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
    /// <p>The prefix of the stream name of the CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
}
impl CloudWatchLogsConfig {
    /// Creates a new builder-style object to manufacture [`CloudWatchLogsConfig`](crate::types::CloudWatchLogsConfig).
    pub fn builder() -> crate::types::builders::CloudWatchLogsConfigBuilder {
        crate::types::builders::CloudWatchLogsConfigBuilder::default()
    }
}

/// A builder for [`CloudWatchLogsConfig`](crate::types::CloudWatchLogsConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchLogsConfigBuilder {
    pub(crate) status: ::std::option::Option<crate::types::LogsConfigStatusType>,
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsConfigBuilder {
    /// <p>The current status of the logs in CloudWatch Logs for a build project. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code>: CloudWatch Logs are enabled for this build project.</p></li>
    /// <li>
    /// <p><code>DISABLED</code>: CloudWatch Logs are not enabled for this build project.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::LogsConfigStatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the logs in CloudWatch Logs for a build project. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code>: CloudWatch Logs are enabled for this build project.</p></li>
    /// <li>
    /// <p><code>DISABLED</code>: CloudWatch Logs are not enabled for this build project.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::LogsConfigStatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the logs in CloudWatch Logs for a build project. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code>: CloudWatch Logs are enabled for this build project.</p></li>
    /// <li>
    /// <p><code>DISABLED</code>: CloudWatch Logs are not enabled for this build project.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::LogsConfigStatusType> {
        &self.status
    }
    /// <p>The group name of the logs in CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The group name of the logs in CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The group name of the logs in CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// <p>The prefix of the stream name of the CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix of the stream name of the CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The prefix of the stream name of the CloudWatch Logs. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html">Working with Log Groups and Log Streams</a>.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// Consumes the builder and constructs a [`CloudWatchLogsConfig`](crate::types::CloudWatchLogsConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::CloudWatchLogsConfigBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::CloudWatchLogsConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudWatchLogsConfig {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building CloudWatchLogsConfig",
                )
            })?,
            group_name: self.group_name,
            stream_name: self.stream_name,
        })
    }
}
