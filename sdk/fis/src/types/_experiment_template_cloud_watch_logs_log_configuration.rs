// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the configuration for experiment logging to Amazon CloudWatch Logs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExperimentTemplateCloudWatchLogsLogConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the destination Amazon CloudWatch Logs log group.</p>
    pub log_group_arn: ::std::option::Option<::std::string::String>,
}
impl ExperimentTemplateCloudWatchLogsLogConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the destination Amazon CloudWatch Logs log group.</p>
    pub fn log_group_arn(&self) -> ::std::option::Option<&str> {
        self.log_group_arn.as_deref()
    }
}
impl ExperimentTemplateCloudWatchLogsLogConfiguration {
    /// Creates a new builder-style object to manufacture [`ExperimentTemplateCloudWatchLogsLogConfiguration`](crate::types::ExperimentTemplateCloudWatchLogsLogConfiguration).
    pub fn builder() -> crate::types::builders::ExperimentTemplateCloudWatchLogsLogConfigurationBuilder {
        crate::types::builders::ExperimentTemplateCloudWatchLogsLogConfigurationBuilder::default()
    }
}

/// A builder for [`ExperimentTemplateCloudWatchLogsLogConfiguration`](crate::types::ExperimentTemplateCloudWatchLogsLogConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExperimentTemplateCloudWatchLogsLogConfigurationBuilder {
    pub(crate) log_group_arn: ::std::option::Option<::std::string::String>,
}
impl ExperimentTemplateCloudWatchLogsLogConfigurationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the destination Amazon CloudWatch Logs log group.</p>
    pub fn log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the destination Amazon CloudWatch Logs log group.</p>
    pub fn set_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the destination Amazon CloudWatch Logs log group.</p>
    pub fn get_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_arn
    }
    /// Consumes the builder and constructs a [`ExperimentTemplateCloudWatchLogsLogConfiguration`](crate::types::ExperimentTemplateCloudWatchLogsLogConfiguration).
    pub fn build(self) -> crate::types::ExperimentTemplateCloudWatchLogsLogConfiguration {
        crate::types::ExperimentTemplateCloudWatchLogsLogConfiguration {
            log_group_arn: self.log_group_arn,
        }
    }
}
