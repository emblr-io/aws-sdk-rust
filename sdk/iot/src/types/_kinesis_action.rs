// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an action to write data to an Amazon Kinesis stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KinesisAction {
    /// <p>The ARN of the IAM role that grants access to the Amazon Kinesis stream.</p>
    pub role_arn: ::std::string::String,
    /// <p>The name of the Amazon Kinesis stream.</p>
    pub stream_name: ::std::string::String,
    /// <p>The partition key.</p>
    pub partition_key: ::std::option::Option<::std::string::String>,
}
impl KinesisAction {
    /// <p>The ARN of the IAM role that grants access to the Amazon Kinesis stream.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The name of the Amazon Kinesis stream.</p>
    pub fn stream_name(&self) -> &str {
        use std::ops::Deref;
        self.stream_name.deref()
    }
    /// <p>The partition key.</p>
    pub fn partition_key(&self) -> ::std::option::Option<&str> {
        self.partition_key.as_deref()
    }
}
impl KinesisAction {
    /// Creates a new builder-style object to manufacture [`KinesisAction`](crate::types::KinesisAction).
    pub fn builder() -> crate::types::builders::KinesisActionBuilder {
        crate::types::builders::KinesisActionBuilder::default()
    }
}

/// A builder for [`KinesisAction`](crate::types::KinesisAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KinesisActionBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) partition_key: ::std::option::Option<::std::string::String>,
}
impl KinesisActionBuilder {
    /// <p>The ARN of the IAM role that grants access to the Amazon Kinesis stream.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role that grants access to the Amazon Kinesis stream.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role that grants access to the Amazon Kinesis stream.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The name of the Amazon Kinesis stream.</p>
    /// This field is required.
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Kinesis stream.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the Amazon Kinesis stream.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The partition key.</p>
    pub fn partition_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.partition_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The partition key.</p>
    pub fn set_partition_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.partition_key = input;
        self
    }
    /// <p>The partition key.</p>
    pub fn get_partition_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.partition_key
    }
    /// Consumes the builder and constructs a [`KinesisAction`](crate::types::KinesisAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_arn`](crate::types::builders::KinesisActionBuilder::role_arn)
    /// - [`stream_name`](crate::types::builders::KinesisActionBuilder::stream_name)
    pub fn build(self) -> ::std::result::Result<crate::types::KinesisAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::KinesisAction {
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building KinesisAction",
                )
            })?,
            stream_name: self.stream_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stream_name",
                    "stream_name was not specified but it is required when building KinesisAction",
                )
            })?,
            partition_key: self.partition_key,
        })
    }
}
