// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Access log settings, including the access log format and access log destination ARN.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessLogSettings {
    /// <p>A single line format of the access logs of data, as specified by selected $context variables. The format must include at least <code>$context.requestId</code>.</p>
    pub format: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or Kinesis Data Firehose delivery stream to receive access logs. If you specify a Kinesis Data Firehose delivery stream, the stream name must begin with <code>amazon-apigateway-</code>.</p>
    pub destination_arn: ::std::option::Option<::std::string::String>,
}
impl AccessLogSettings {
    /// <p>A single line format of the access logs of data, as specified by selected $context variables. The format must include at least <code>$context.requestId</code>.</p>
    pub fn format(&self) -> ::std::option::Option<&str> {
        self.format.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or Kinesis Data Firehose delivery stream to receive access logs. If you specify a Kinesis Data Firehose delivery stream, the stream name must begin with <code>amazon-apigateway-</code>.</p>
    pub fn destination_arn(&self) -> ::std::option::Option<&str> {
        self.destination_arn.as_deref()
    }
}
impl AccessLogSettings {
    /// Creates a new builder-style object to manufacture [`AccessLogSettings`](crate::types::AccessLogSettings).
    pub fn builder() -> crate::types::builders::AccessLogSettingsBuilder {
        crate::types::builders::AccessLogSettingsBuilder::default()
    }
}

/// A builder for [`AccessLogSettings`](crate::types::AccessLogSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessLogSettingsBuilder {
    pub(crate) format: ::std::option::Option<::std::string::String>,
    pub(crate) destination_arn: ::std::option::Option<::std::string::String>,
}
impl AccessLogSettingsBuilder {
    /// <p>A single line format of the access logs of data, as specified by selected $context variables. The format must include at least <code>$context.requestId</code>.</p>
    pub fn format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A single line format of the access logs of data, as specified by selected $context variables. The format must include at least <code>$context.requestId</code>.</p>
    pub fn set_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.format = input;
        self
    }
    /// <p>A single line format of the access logs of data, as specified by selected $context variables. The format must include at least <code>$context.requestId</code>.</p>
    pub fn get_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.format
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or Kinesis Data Firehose delivery stream to receive access logs. If you specify a Kinesis Data Firehose delivery stream, the stream name must begin with <code>amazon-apigateway-</code>.</p>
    pub fn destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or Kinesis Data Firehose delivery stream to receive access logs. If you specify a Kinesis Data Firehose delivery stream, the stream name must begin with <code>amazon-apigateway-</code>.</p>
    pub fn set_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Logs log group or Kinesis Data Firehose delivery stream to receive access logs. If you specify a Kinesis Data Firehose delivery stream, the stream name must begin with <code>amazon-apigateway-</code>.</p>
    pub fn get_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_arn
    }
    /// Consumes the builder and constructs a [`AccessLogSettings`](crate::types::AccessLogSettings).
    pub fn build(self) -> crate::types::AccessLogSettings {
        crate::types::AccessLogSettings {
            format: self.format,
            destination_arn: self.destination_arn,
        }
    }
}
