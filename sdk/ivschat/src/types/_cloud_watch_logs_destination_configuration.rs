// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a CloudWatch Logs location where chat logs will be stored.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLogsDestinationConfiguration {
    /// <p>Name of the Amazon Cloudwatch Logs destination where chat activity will be logged.</p>
    pub log_group_name: ::std::string::String,
}
impl CloudWatchLogsDestinationConfiguration {
    /// <p>Name of the Amazon Cloudwatch Logs destination where chat activity will be logged.</p>
    pub fn log_group_name(&self) -> &str {
        use std::ops::Deref;
        self.log_group_name.deref()
    }
}
impl CloudWatchLogsDestinationConfiguration {
    /// Creates a new builder-style object to manufacture [`CloudWatchLogsDestinationConfiguration`](crate::types::CloudWatchLogsDestinationConfiguration).
    pub fn builder() -> crate::types::builders::CloudWatchLogsDestinationConfigurationBuilder {
        crate::types::builders::CloudWatchLogsDestinationConfigurationBuilder::default()
    }
}

/// A builder for [`CloudWatchLogsDestinationConfiguration`](crate::types::CloudWatchLogsDestinationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchLogsDestinationConfigurationBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLogsDestinationConfigurationBuilder {
    /// <p>Name of the Amazon Cloudwatch Logs destination where chat activity will be logged.</p>
    /// This field is required.
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the Amazon Cloudwatch Logs destination where chat activity will be logged.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>Name of the Amazon Cloudwatch Logs destination where chat activity will be logged.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// Consumes the builder and constructs a [`CloudWatchLogsDestinationConfiguration`](crate::types::CloudWatchLogsDestinationConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`log_group_name`](crate::types::builders::CloudWatchLogsDestinationConfigurationBuilder::log_group_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::CloudWatchLogsDestinationConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudWatchLogsDestinationConfiguration {
            log_group_name: self.log_group_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "log_group_name",
                    "log_group_name was not specified but it is required when building CloudWatchLogsDestinationConfiguration",
                )
            })?,
        })
    }
}
