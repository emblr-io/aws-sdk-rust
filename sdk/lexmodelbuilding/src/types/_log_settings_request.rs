// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Settings used to configure delivery mode and destination for conversation logs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogSettingsRequest {
    /// <p>The type of logging to enable. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub log_type: crate::types::LogType,
    /// <p>Where the logs will be delivered. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub destination: crate::types::Destination,
    /// <p>The Amazon Resource Name (ARN) of the AWS KMS customer managed key for encrypting audio logs delivered to an S3 bucket. The key does not apply to CloudWatch Logs and is optional for S3 buckets.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs should be delivered.</p>
    pub resource_arn: ::std::string::String,
}
impl LogSettingsRequest {
    /// <p>The type of logging to enable. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn log_type(&self) -> &crate::types::LogType {
        &self.log_type
    }
    /// <p>Where the logs will be delivered. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn destination(&self) -> &crate::types::Destination {
        &self.destination
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS KMS customer managed key for encrypting audio logs delivered to an S3 bucket. The key does not apply to CloudWatch Logs and is optional for S3 buckets.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs should be delivered.</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
}
impl LogSettingsRequest {
    /// Creates a new builder-style object to manufacture [`LogSettingsRequest`](crate::types::LogSettingsRequest).
    pub fn builder() -> crate::types::builders::LogSettingsRequestBuilder {
        crate::types::builders::LogSettingsRequestBuilder::default()
    }
}

/// A builder for [`LogSettingsRequest`](crate::types::LogSettingsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogSettingsRequestBuilder {
    pub(crate) log_type: ::std::option::Option<crate::types::LogType>,
    pub(crate) destination: ::std::option::Option<crate::types::Destination>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl LogSettingsRequestBuilder {
    /// <p>The type of logging to enable. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    /// This field is required.
    pub fn log_type(mut self, input: crate::types::LogType) -> Self {
        self.log_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of logging to enable. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn set_log_type(mut self, input: ::std::option::Option<crate::types::LogType>) -> Self {
        self.log_type = input;
        self
    }
    /// <p>The type of logging to enable. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn get_log_type(&self) -> &::std::option::Option<crate::types::LogType> {
        &self.log_type
    }
    /// <p>Where the logs will be delivered. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::Destination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Where the logs will be delivered. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::Destination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>Where the logs will be delivered. Text logs are delivered to a CloudWatch Logs log group. Audio logs are delivered to an S3 bucket.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::Destination> {
        &self.destination
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS KMS customer managed key for encrypting audio logs delivered to an S3 bucket. The key does not apply to CloudWatch Logs and is optional for S3 buckets.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS KMS customer managed key for encrypting audio logs delivered to an S3 bucket. The key does not apply to CloudWatch Logs and is optional for S3 buckets.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS KMS customer managed key for encrypting audio logs delivered to an S3 bucket. The key does not apply to CloudWatch Logs and is optional for S3 buckets.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs should be delivered.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs should be delivered.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or S3 bucket where the logs should be delivered.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`LogSettingsRequest`](crate::types::LogSettingsRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`log_type`](crate::types::builders::LogSettingsRequestBuilder::log_type)
    /// - [`destination`](crate::types::builders::LogSettingsRequestBuilder::destination)
    /// - [`resource_arn`](crate::types::builders::LogSettingsRequestBuilder::resource_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::LogSettingsRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LogSettingsRequest {
            log_type: self.log_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "log_type",
                    "log_type was not specified but it is required when building LogSettingsRequest",
                )
            })?,
            destination: self.destination.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "destination",
                    "destination was not specified but it is required when building LogSettingsRequest",
                )
            })?,
            kms_key_arn: self.kms_key_arn,
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building LogSettingsRequest",
                )
            })?,
        })
    }
}
