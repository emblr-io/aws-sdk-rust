// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output configuration details for a metric attribution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricAttributionOutput {
    /// <p>The configuration details of an Amazon S3 input or output bucket.</p>
    pub s3_data_destination: ::std::option::Option<crate::types::S3DataConfig>,
    /// <p>The Amazon Resource Name (ARN) of the IAM service role that has permissions to add data to your output Amazon S3 bucket and add metrics to Amazon CloudWatch. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub role_arn: ::std::string::String,
}
impl MetricAttributionOutput {
    /// <p>The configuration details of an Amazon S3 input or output bucket.</p>
    pub fn s3_data_destination(&self) -> ::std::option::Option<&crate::types::S3DataConfig> {
        self.s3_data_destination.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role that has permissions to add data to your output Amazon S3 bucket and add metrics to Amazon CloudWatch. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
}
impl MetricAttributionOutput {
    /// Creates a new builder-style object to manufacture [`MetricAttributionOutput`](crate::types::MetricAttributionOutput).
    pub fn builder() -> crate::types::builders::MetricAttributionOutputBuilder {
        crate::types::builders::MetricAttributionOutputBuilder::default()
    }
}

/// A builder for [`MetricAttributionOutput`](crate::types::MetricAttributionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricAttributionOutputBuilder {
    pub(crate) s3_data_destination: ::std::option::Option<crate::types::S3DataConfig>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl MetricAttributionOutputBuilder {
    /// <p>The configuration details of an Amazon S3 input or output bucket.</p>
    pub fn s3_data_destination(mut self, input: crate::types::S3DataConfig) -> Self {
        self.s3_data_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration details of an Amazon S3 input or output bucket.</p>
    pub fn set_s3_data_destination(mut self, input: ::std::option::Option<crate::types::S3DataConfig>) -> Self {
        self.s3_data_destination = input;
        self
    }
    /// <p>The configuration details of an Amazon S3 input or output bucket.</p>
    pub fn get_s3_data_destination(&self) -> &::std::option::Option<crate::types::S3DataConfig> {
        &self.s3_data_destination
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role that has permissions to add data to your output Amazon S3 bucket and add metrics to Amazon CloudWatch. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role that has permissions to add data to your output Amazon S3 bucket and add metrics to Amazon CloudWatch. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM service role that has permissions to add data to your output Amazon S3 bucket and add metrics to Amazon CloudWatch. For more information, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`MetricAttributionOutput`](crate::types::MetricAttributionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_arn`](crate::types::builders::MetricAttributionOutputBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::MetricAttributionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MetricAttributionOutput {
            s3_data_destination: self.s3_data_destination,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building MetricAttributionOutput",
                )
            })?,
        })
    }
}
