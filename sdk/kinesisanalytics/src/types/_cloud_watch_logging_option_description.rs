// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Description of the CloudWatch logging option.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudWatchLoggingOptionDescription {
    /// <p>ID of the CloudWatch logging option description.</p>
    pub cloud_watch_logging_option_id: ::std::option::Option<::std::string::String>,
    /// <p>ARN of the CloudWatch log to receive application messages.</p>
    pub log_stream_arn: ::std::string::String,
    /// <p>IAM ARN of the role to use to send application messages. Note: To write application messages to CloudWatch, the IAM role used must have the <code>PutLogEvents</code> policy action enabled.</p>
    pub role_arn: ::std::string::String,
}
impl CloudWatchLoggingOptionDescription {
    /// <p>ID of the CloudWatch logging option description.</p>
    pub fn cloud_watch_logging_option_id(&self) -> ::std::option::Option<&str> {
        self.cloud_watch_logging_option_id.as_deref()
    }
    /// <p>ARN of the CloudWatch log to receive application messages.</p>
    pub fn log_stream_arn(&self) -> &str {
        use std::ops::Deref;
        self.log_stream_arn.deref()
    }
    /// <p>IAM ARN of the role to use to send application messages. Note: To write application messages to CloudWatch, the IAM role used must have the <code>PutLogEvents</code> policy action enabled.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
}
impl CloudWatchLoggingOptionDescription {
    /// Creates a new builder-style object to manufacture [`CloudWatchLoggingOptionDescription`](crate::types::CloudWatchLoggingOptionDescription).
    pub fn builder() -> crate::types::builders::CloudWatchLoggingOptionDescriptionBuilder {
        crate::types::builders::CloudWatchLoggingOptionDescriptionBuilder::default()
    }
}

/// A builder for [`CloudWatchLoggingOptionDescription`](crate::types::CloudWatchLoggingOptionDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudWatchLoggingOptionDescriptionBuilder {
    pub(crate) cloud_watch_logging_option_id: ::std::option::Option<::std::string::String>,
    pub(crate) log_stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl CloudWatchLoggingOptionDescriptionBuilder {
    /// <p>ID of the CloudWatch logging option description.</p>
    pub fn cloud_watch_logging_option_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_watch_logging_option_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of the CloudWatch logging option description.</p>
    pub fn set_cloud_watch_logging_option_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_watch_logging_option_id = input;
        self
    }
    /// <p>ID of the CloudWatch logging option description.</p>
    pub fn get_cloud_watch_logging_option_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_watch_logging_option_id
    }
    /// <p>ARN of the CloudWatch log to receive application messages.</p>
    /// This field is required.
    pub fn log_stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the CloudWatch log to receive application messages.</p>
    pub fn set_log_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_stream_arn = input;
        self
    }
    /// <p>ARN of the CloudWatch log to receive application messages.</p>
    pub fn get_log_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_stream_arn
    }
    /// <p>IAM ARN of the role to use to send application messages. Note: To write application messages to CloudWatch, the IAM role used must have the <code>PutLogEvents</code> policy action enabled.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>IAM ARN of the role to use to send application messages. Note: To write application messages to CloudWatch, the IAM role used must have the <code>PutLogEvents</code> policy action enabled.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>IAM ARN of the role to use to send application messages. Note: To write application messages to CloudWatch, the IAM role used must have the <code>PutLogEvents</code> policy action enabled.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`CloudWatchLoggingOptionDescription`](crate::types::CloudWatchLoggingOptionDescription).
    /// This method will fail if any of the following fields are not set:
    /// - [`log_stream_arn`](crate::types::builders::CloudWatchLoggingOptionDescriptionBuilder::log_stream_arn)
    /// - [`role_arn`](crate::types::builders::CloudWatchLoggingOptionDescriptionBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::CloudWatchLoggingOptionDescription, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CloudWatchLoggingOptionDescription {
            cloud_watch_logging_option_id: self.cloud_watch_logging_option_id,
            log_stream_arn: self.log_stream_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "log_stream_arn",
                    "log_stream_arn was not specified but it is required when building CloudWatchLoggingOptionDescription",
                )
            })?,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building CloudWatchLoggingOptionDescription",
                )
            })?,
        })
    }
}
