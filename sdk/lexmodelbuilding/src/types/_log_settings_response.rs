// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for conversation logs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogSettingsResponse {
    /// <p>The type of logging that is enabled.</p>
    pub log_type: ::std::option::Option<crate::types::LogType>,
    /// <p>The destination where logs are delivered.</p>
    pub destination: ::std::option::Option<crate::types::Destination>,
    /// <p>The Amazon Resource Name (ARN) of the key used to encrypt audio logs in an S3 bucket.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs are delivered.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The resource prefix is the first part of the S3 object key within the S3 bucket that you specified to contain audio logs. For CloudWatch Logs it is the prefix of the log stream name within the log group that you specified.</p>
    pub resource_prefix: ::std::option::Option<::std::string::String>,
}
impl LogSettingsResponse {
    /// <p>The type of logging that is enabled.</p>
    pub fn log_type(&self) -> ::std::option::Option<&crate::types::LogType> {
        self.log_type.as_ref()
    }
    /// <p>The destination where logs are delivered.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::Destination> {
        self.destination.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the key used to encrypt audio logs in an S3 bucket.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs are delivered.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The resource prefix is the first part of the S3 object key within the S3 bucket that you specified to contain audio logs. For CloudWatch Logs it is the prefix of the log stream name within the log group that you specified.</p>
    pub fn resource_prefix(&self) -> ::std::option::Option<&str> {
        self.resource_prefix.as_deref()
    }
}
impl LogSettingsResponse {
    /// Creates a new builder-style object to manufacture [`LogSettingsResponse`](crate::types::LogSettingsResponse).
    pub fn builder() -> crate::types::builders::LogSettingsResponseBuilder {
        crate::types::builders::LogSettingsResponseBuilder::default()
    }
}

/// A builder for [`LogSettingsResponse`](crate::types::LogSettingsResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogSettingsResponseBuilder {
    pub(crate) log_type: ::std::option::Option<crate::types::LogType>,
    pub(crate) destination: ::std::option::Option<crate::types::Destination>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_prefix: ::std::option::Option<::std::string::String>,
}
impl LogSettingsResponseBuilder {
    /// <p>The type of logging that is enabled.</p>
    pub fn log_type(mut self, input: crate::types::LogType) -> Self {
        self.log_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of logging that is enabled.</p>
    pub fn set_log_type(mut self, input: ::std::option::Option<crate::types::LogType>) -> Self {
        self.log_type = input;
        self
    }
    /// <p>The type of logging that is enabled.</p>
    pub fn get_log_type(&self) -> &::std::option::Option<crate::types::LogType> {
        &self.log_type
    }
    /// <p>The destination where logs are delivered.</p>
    pub fn destination(mut self, input: crate::types::Destination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The destination where logs are delivered.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::Destination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>The destination where logs are delivered.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::Destination> {
        &self.destination
    }
    /// <p>The Amazon Resource Name (ARN) of the key used to encrypt audio logs in an S3 bucket.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the key used to encrypt audio logs in an S3 bucket.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the key used to encrypt audio logs in an S3 bucket.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs are delivered.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs are delivered.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs are delivered.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The resource prefix is the first part of the S3 object key within the S3 bucket that you specified to contain audio logs. For CloudWatch Logs it is the prefix of the log stream name within the log group that you specified.</p>
    pub fn resource_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource prefix is the first part of the S3 object key within the S3 bucket that you specified to contain audio logs. For CloudWatch Logs it is the prefix of the log stream name within the log group that you specified.</p>
    pub fn set_resource_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_prefix = input;
        self
    }
    /// <p>The resource prefix is the first part of the S3 object key within the S3 bucket that you specified to contain audio logs. For CloudWatch Logs it is the prefix of the log stream name within the log group that you specified.</p>
    pub fn get_resource_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_prefix
    }
    /// Consumes the builder and constructs a [`LogSettingsResponse`](crate::types::LogSettingsResponse).
    pub fn build(self) -> crate::types::LogSettingsResponse {
        crate::types::LogSettingsResponse {
            log_type: self.log_type,
            destination: self.destination,
            kms_key_arn: self.kms_key_arn,
            resource_arn: self.resource_arn,
            resource_prefix: self.resource_prefix,
        }
    }
}
