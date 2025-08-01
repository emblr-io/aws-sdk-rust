// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DestinationDetails {
    /// <p>The configuration details of the CloudWatch Logs destination.</p>
    pub cloud_watch_logs_details: ::std::option::Option<crate::types::CloudWatchLogsDestinationDetails>,
    /// <p>The configuration details of the Kinesis Data Firehose destination.</p>
    pub kinesis_firehose_details: ::std::option::Option<crate::types::KinesisFirehoseDestinationDetails>,
}
impl DestinationDetails {
    /// <p>The configuration details of the CloudWatch Logs destination.</p>
    pub fn cloud_watch_logs_details(&self) -> ::std::option::Option<&crate::types::CloudWatchLogsDestinationDetails> {
        self.cloud_watch_logs_details.as_ref()
    }
    /// <p>The configuration details of the Kinesis Data Firehose destination.</p>
    pub fn kinesis_firehose_details(&self) -> ::std::option::Option<&crate::types::KinesisFirehoseDestinationDetails> {
        self.kinesis_firehose_details.as_ref()
    }
}
impl DestinationDetails {
    /// Creates a new builder-style object to manufacture [`DestinationDetails`](crate::types::DestinationDetails).
    pub fn builder() -> crate::types::builders::DestinationDetailsBuilder {
        crate::types::builders::DestinationDetailsBuilder::default()
    }
}

/// A builder for [`DestinationDetails`](crate::types::DestinationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationDetailsBuilder {
    pub(crate) cloud_watch_logs_details: ::std::option::Option<crate::types::CloudWatchLogsDestinationDetails>,
    pub(crate) kinesis_firehose_details: ::std::option::Option<crate::types::KinesisFirehoseDestinationDetails>,
}
impl DestinationDetailsBuilder {
    /// <p>The configuration details of the CloudWatch Logs destination.</p>
    pub fn cloud_watch_logs_details(mut self, input: crate::types::CloudWatchLogsDestinationDetails) -> Self {
        self.cloud_watch_logs_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration details of the CloudWatch Logs destination.</p>
    pub fn set_cloud_watch_logs_details(mut self, input: ::std::option::Option<crate::types::CloudWatchLogsDestinationDetails>) -> Self {
        self.cloud_watch_logs_details = input;
        self
    }
    /// <p>The configuration details of the CloudWatch Logs destination.</p>
    pub fn get_cloud_watch_logs_details(&self) -> &::std::option::Option<crate::types::CloudWatchLogsDestinationDetails> {
        &self.cloud_watch_logs_details
    }
    /// <p>The configuration details of the Kinesis Data Firehose destination.</p>
    pub fn kinesis_firehose_details(mut self, input: crate::types::KinesisFirehoseDestinationDetails) -> Self {
        self.kinesis_firehose_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration details of the Kinesis Data Firehose destination.</p>
    pub fn set_kinesis_firehose_details(mut self, input: ::std::option::Option<crate::types::KinesisFirehoseDestinationDetails>) -> Self {
        self.kinesis_firehose_details = input;
        self
    }
    /// <p>The configuration details of the Kinesis Data Firehose destination.</p>
    pub fn get_kinesis_firehose_details(&self) -> &::std::option::Option<crate::types::KinesisFirehoseDestinationDetails> {
        &self.kinesis_firehose_details
    }
    /// Consumes the builder and constructs a [`DestinationDetails`](crate::types::DestinationDetails).
    pub fn build(self) -> crate::types::DestinationDetails {
        crate::types::DestinationDetails {
            cloud_watch_logs_details: self.cloud_watch_logs_details,
            kinesis_firehose_details: self.kinesis_firehose_details,
        }
    }
}
