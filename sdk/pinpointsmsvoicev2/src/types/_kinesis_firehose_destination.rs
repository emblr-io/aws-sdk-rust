// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the delivery stream Amazon Resource Name (ARN), and the ARN of the Identity and Access Management (IAM) role associated with a Firehose event destination.</p>
/// <p>Event destinations, such as Firehose, are associated with configuration sets, which enable you to publish message sending events.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KinesisFirehoseDestination {
    /// <p>The ARN of an Identity and Access Management role that is able to write event data to an Amazon Data Firehose destination.</p>
    pub iam_role_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the delivery stream.</p>
    pub delivery_stream_arn: ::std::string::String,
}
impl KinesisFirehoseDestination {
    /// <p>The ARN of an Identity and Access Management role that is able to write event data to an Amazon Data Firehose destination.</p>
    pub fn iam_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.iam_role_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the delivery stream.</p>
    pub fn delivery_stream_arn(&self) -> &str {
        use std::ops::Deref;
        self.delivery_stream_arn.deref()
    }
}
impl KinesisFirehoseDestination {
    /// Creates a new builder-style object to manufacture [`KinesisFirehoseDestination`](crate::types::KinesisFirehoseDestination).
    pub fn builder() -> crate::types::builders::KinesisFirehoseDestinationBuilder {
        crate::types::builders::KinesisFirehoseDestinationBuilder::default()
    }
}

/// A builder for [`KinesisFirehoseDestination`](crate::types::KinesisFirehoseDestination).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KinesisFirehoseDestinationBuilder {
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) delivery_stream_arn: ::std::option::Option<::std::string::String>,
}
impl KinesisFirehoseDestinationBuilder {
    /// <p>The ARN of an Identity and Access Management role that is able to write event data to an Amazon Data Firehose destination.</p>
    /// This field is required.
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of an Identity and Access Management role that is able to write event data to an Amazon Data Firehose destination.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>The ARN of an Identity and Access Management role that is able to write event data to an Amazon Data Firehose destination.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the delivery stream.</p>
    /// This field is required.
    pub fn delivery_stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the delivery stream.</p>
    pub fn set_delivery_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the delivery stream.</p>
    pub fn get_delivery_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream_arn
    }
    /// Consumes the builder and constructs a [`KinesisFirehoseDestination`](crate::types::KinesisFirehoseDestination).
    /// This method will fail if any of the following fields are not set:
    /// - [`iam_role_arn`](crate::types::builders::KinesisFirehoseDestinationBuilder::iam_role_arn)
    /// - [`delivery_stream_arn`](crate::types::builders::KinesisFirehoseDestinationBuilder::delivery_stream_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::KinesisFirehoseDestination, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::KinesisFirehoseDestination {
            iam_role_arn: self.iam_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "iam_role_arn",
                    "iam_role_arn was not specified but it is required when building KinesisFirehoseDestination",
                )
            })?,
            delivery_stream_arn: self.delivery_stream_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "delivery_stream_arn",
                    "delivery_stream_arn was not specified but it is required when building KinesisFirehoseDestination",
                )
            })?,
        })
    }
}
