// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Attributes of a custom routing accelerator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomRoutingAcceleratorAttributes {
    /// <p>Indicates whether flow logs are enabled. The default value is false. If the value is true, <code>FlowLogsS3Bucket</code> and <code>FlowLogsS3Prefix</code> must be specified.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html">Flow logs</a> in the <i>Global Accelerator Developer Guide</i>.</p>
    pub flow_logs_enabled: ::std::option::Option<bool>,
    /// <p>The name of the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>. The bucket must exist and have a bucket policy that grants Global Accelerator permission to write to the bucket.</p>
    pub flow_logs_s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The prefix for the location in the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>.</p>
    /// <p>If you don’t specify a prefix, the flow logs are stored in the root of the bucket. If you specify slash (/) for the S3 bucket prefix, the log file bucket folder structure will include a double slash (//), like the following:</p>
    /// <p>DOC-EXAMPLE-BUCKET//AWSLogs/aws_account_id</p>
    pub flow_logs_s3_prefix: ::std::option::Option<::std::string::String>,
}
impl CustomRoutingAcceleratorAttributes {
    /// <p>Indicates whether flow logs are enabled. The default value is false. If the value is true, <code>FlowLogsS3Bucket</code> and <code>FlowLogsS3Prefix</code> must be specified.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html">Flow logs</a> in the <i>Global Accelerator Developer Guide</i>.</p>
    pub fn flow_logs_enabled(&self) -> ::std::option::Option<bool> {
        self.flow_logs_enabled
    }
    /// <p>The name of the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>. The bucket must exist and have a bucket policy that grants Global Accelerator permission to write to the bucket.</p>
    pub fn flow_logs_s3_bucket(&self) -> ::std::option::Option<&str> {
        self.flow_logs_s3_bucket.as_deref()
    }
    /// <p>The prefix for the location in the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>.</p>
    /// <p>If you don’t specify a prefix, the flow logs are stored in the root of the bucket. If you specify slash (/) for the S3 bucket prefix, the log file bucket folder structure will include a double slash (//), like the following:</p>
    /// <p>DOC-EXAMPLE-BUCKET//AWSLogs/aws_account_id</p>
    pub fn flow_logs_s3_prefix(&self) -> ::std::option::Option<&str> {
        self.flow_logs_s3_prefix.as_deref()
    }
}
impl CustomRoutingAcceleratorAttributes {
    /// Creates a new builder-style object to manufacture [`CustomRoutingAcceleratorAttributes`](crate::types::CustomRoutingAcceleratorAttributes).
    pub fn builder() -> crate::types::builders::CustomRoutingAcceleratorAttributesBuilder {
        crate::types::builders::CustomRoutingAcceleratorAttributesBuilder::default()
    }
}

/// A builder for [`CustomRoutingAcceleratorAttributes`](crate::types::CustomRoutingAcceleratorAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomRoutingAcceleratorAttributesBuilder {
    pub(crate) flow_logs_enabled: ::std::option::Option<bool>,
    pub(crate) flow_logs_s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) flow_logs_s3_prefix: ::std::option::Option<::std::string::String>,
}
impl CustomRoutingAcceleratorAttributesBuilder {
    /// <p>Indicates whether flow logs are enabled. The default value is false. If the value is true, <code>FlowLogsS3Bucket</code> and <code>FlowLogsS3Prefix</code> must be specified.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html">Flow logs</a> in the <i>Global Accelerator Developer Guide</i>.</p>
    pub fn flow_logs_enabled(mut self, input: bool) -> Self {
        self.flow_logs_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether flow logs are enabled. The default value is false. If the value is true, <code>FlowLogsS3Bucket</code> and <code>FlowLogsS3Prefix</code> must be specified.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html">Flow logs</a> in the <i>Global Accelerator Developer Guide</i>.</p>
    pub fn set_flow_logs_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.flow_logs_enabled = input;
        self
    }
    /// <p>Indicates whether flow logs are enabled. The default value is false. If the value is true, <code>FlowLogsS3Bucket</code> and <code>FlowLogsS3Prefix</code> must be specified.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html">Flow logs</a> in the <i>Global Accelerator Developer Guide</i>.</p>
    pub fn get_flow_logs_enabled(&self) -> &::std::option::Option<bool> {
        &self.flow_logs_enabled
    }
    /// <p>The name of the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>. The bucket must exist and have a bucket policy that grants Global Accelerator permission to write to the bucket.</p>
    pub fn flow_logs_s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_logs_s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>. The bucket must exist and have a bucket policy that grants Global Accelerator permission to write to the bucket.</p>
    pub fn set_flow_logs_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_logs_s3_bucket = input;
        self
    }
    /// <p>The name of the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>. The bucket must exist and have a bucket policy that grants Global Accelerator permission to write to the bucket.</p>
    pub fn get_flow_logs_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_logs_s3_bucket
    }
    /// <p>The prefix for the location in the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>.</p>
    /// <p>If you don’t specify a prefix, the flow logs are stored in the root of the bucket. If you specify slash (/) for the S3 bucket prefix, the log file bucket folder structure will include a double slash (//), like the following:</p>
    /// <p>DOC-EXAMPLE-BUCKET//AWSLogs/aws_account_id</p>
    pub fn flow_logs_s3_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_logs_s3_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The prefix for the location in the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>.</p>
    /// <p>If you don’t specify a prefix, the flow logs are stored in the root of the bucket. If you specify slash (/) for the S3 bucket prefix, the log file bucket folder structure will include a double slash (//), like the following:</p>
    /// <p>DOC-EXAMPLE-BUCKET//AWSLogs/aws_account_id</p>
    pub fn set_flow_logs_s3_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_logs_s3_prefix = input;
        self
    }
    /// <p>The prefix for the location in the Amazon S3 bucket for the flow logs. Attribute is required if <code>FlowLogsEnabled</code> is <code>true</code>.</p>
    /// <p>If you don’t specify a prefix, the flow logs are stored in the root of the bucket. If you specify slash (/) for the S3 bucket prefix, the log file bucket folder structure will include a double slash (//), like the following:</p>
    /// <p>DOC-EXAMPLE-BUCKET//AWSLogs/aws_account_id</p>
    pub fn get_flow_logs_s3_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_logs_s3_prefix
    }
    /// Consumes the builder and constructs a [`CustomRoutingAcceleratorAttributes`](crate::types::CustomRoutingAcceleratorAttributes).
    pub fn build(self) -> crate::types::CustomRoutingAcceleratorAttributes {
        crate::types::CustomRoutingAcceleratorAttributes {
            flow_logs_enabled: self.flow_logs_enabled,
            flow_logs_s3_bucket: self.flow_logs_s3_bucket,
            flow_logs_s3_prefix: self.flow_logs_s3_prefix,
        }
    }
}
