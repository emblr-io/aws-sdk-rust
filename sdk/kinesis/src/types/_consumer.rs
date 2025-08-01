// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the details of the consumer you registered. This type of object is returned by <code>RegisterStreamConsumer</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Consumer {
    /// <p>The name of the consumer is something you choose when you register the consumer.</p>
    pub consumer_name: ::std::string::String,
    /// <p>When you register a consumer, Kinesis Data Streams generates an ARN for it. You need this ARN to be able to call <code>SubscribeToShard</code>.</p>
    /// <p>If you delete a consumer and then create a new one with the same name, it won't have the same ARN. That's because consumer ARNs contain the creation timestamp. This is important to keep in mind if you have IAM policies that reference consumer ARNs.</p>
    pub consumer_arn: ::std::string::String,
    /// <p>A consumer can't read data while in the <code>CREATING</code> or <code>DELETING</code> states.</p>
    pub consumer_status: crate::types::ConsumerStatus,
    /// <p></p>
    pub consumer_creation_timestamp: ::aws_smithy_types::DateTime,
}
impl Consumer {
    /// <p>The name of the consumer is something you choose when you register the consumer.</p>
    pub fn consumer_name(&self) -> &str {
        use std::ops::Deref;
        self.consumer_name.deref()
    }
    /// <p>When you register a consumer, Kinesis Data Streams generates an ARN for it. You need this ARN to be able to call <code>SubscribeToShard</code>.</p>
    /// <p>If you delete a consumer and then create a new one with the same name, it won't have the same ARN. That's because consumer ARNs contain the creation timestamp. This is important to keep in mind if you have IAM policies that reference consumer ARNs.</p>
    pub fn consumer_arn(&self) -> &str {
        use std::ops::Deref;
        self.consumer_arn.deref()
    }
    /// <p>A consumer can't read data while in the <code>CREATING</code> or <code>DELETING</code> states.</p>
    pub fn consumer_status(&self) -> &crate::types::ConsumerStatus {
        &self.consumer_status
    }
    /// <p></p>
    pub fn consumer_creation_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.consumer_creation_timestamp
    }
}
impl Consumer {
    /// Creates a new builder-style object to manufacture [`Consumer`](crate::types::Consumer).
    pub fn builder() -> crate::types::builders::ConsumerBuilder {
        crate::types::builders::ConsumerBuilder::default()
    }
}

/// A builder for [`Consumer`](crate::types::Consumer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConsumerBuilder {
    pub(crate) consumer_name: ::std::option::Option<::std::string::String>,
    pub(crate) consumer_arn: ::std::option::Option<::std::string::String>,
    pub(crate) consumer_status: ::std::option::Option<crate::types::ConsumerStatus>,
    pub(crate) consumer_creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ConsumerBuilder {
    /// <p>The name of the consumer is something you choose when you register the consumer.</p>
    /// This field is required.
    pub fn consumer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the consumer is something you choose when you register the consumer.</p>
    pub fn set_consumer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumer_name = input;
        self
    }
    /// <p>The name of the consumer is something you choose when you register the consumer.</p>
    pub fn get_consumer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumer_name
    }
    /// <p>When you register a consumer, Kinesis Data Streams generates an ARN for it. You need this ARN to be able to call <code>SubscribeToShard</code>.</p>
    /// <p>If you delete a consumer and then create a new one with the same name, it won't have the same ARN. That's because consumer ARNs contain the creation timestamp. This is important to keep in mind if you have IAM policies that reference consumer ARNs.</p>
    /// This field is required.
    pub fn consumer_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumer_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When you register a consumer, Kinesis Data Streams generates an ARN for it. You need this ARN to be able to call <code>SubscribeToShard</code>.</p>
    /// <p>If you delete a consumer and then create a new one with the same name, it won't have the same ARN. That's because consumer ARNs contain the creation timestamp. This is important to keep in mind if you have IAM policies that reference consumer ARNs.</p>
    pub fn set_consumer_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumer_arn = input;
        self
    }
    /// <p>When you register a consumer, Kinesis Data Streams generates an ARN for it. You need this ARN to be able to call <code>SubscribeToShard</code>.</p>
    /// <p>If you delete a consumer and then create a new one with the same name, it won't have the same ARN. That's because consumer ARNs contain the creation timestamp. This is important to keep in mind if you have IAM policies that reference consumer ARNs.</p>
    pub fn get_consumer_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumer_arn
    }
    /// <p>A consumer can't read data while in the <code>CREATING</code> or <code>DELETING</code> states.</p>
    /// This field is required.
    pub fn consumer_status(mut self, input: crate::types::ConsumerStatus) -> Self {
        self.consumer_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A consumer can't read data while in the <code>CREATING</code> or <code>DELETING</code> states.</p>
    pub fn set_consumer_status(mut self, input: ::std::option::Option<crate::types::ConsumerStatus>) -> Self {
        self.consumer_status = input;
        self
    }
    /// <p>A consumer can't read data while in the <code>CREATING</code> or <code>DELETING</code> states.</p>
    pub fn get_consumer_status(&self) -> &::std::option::Option<crate::types::ConsumerStatus> {
        &self.consumer_status
    }
    /// <p></p>
    /// This field is required.
    pub fn consumer_creation_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.consumer_creation_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_consumer_creation_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.consumer_creation_timestamp = input;
        self
    }
    /// <p></p>
    pub fn get_consumer_creation_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.consumer_creation_timestamp
    }
    /// Consumes the builder and constructs a [`Consumer`](crate::types::Consumer).
    /// This method will fail if any of the following fields are not set:
    /// - [`consumer_name`](crate::types::builders::ConsumerBuilder::consumer_name)
    /// - [`consumer_arn`](crate::types::builders::ConsumerBuilder::consumer_arn)
    /// - [`consumer_status`](crate::types::builders::ConsumerBuilder::consumer_status)
    /// - [`consumer_creation_timestamp`](crate::types::builders::ConsumerBuilder::consumer_creation_timestamp)
    pub fn build(self) -> ::std::result::Result<crate::types::Consumer, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Consumer {
            consumer_name: self.consumer_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "consumer_name",
                    "consumer_name was not specified but it is required when building Consumer",
                )
            })?,
            consumer_arn: self.consumer_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "consumer_arn",
                    "consumer_arn was not specified but it is required when building Consumer",
                )
            })?,
            consumer_status: self.consumer_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "consumer_status",
                    "consumer_status was not specified but it is required when building Consumer",
                )
            })?,
            consumer_creation_timestamp: self.consumer_creation_timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "consumer_creation_timestamp",
                    "consumer_creation_timestamp was not specified but it is required when building Consumer",
                )
            })?,
        })
    }
}
