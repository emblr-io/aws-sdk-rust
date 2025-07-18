// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMetricAttributionInput {
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub metric_attribution_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeMetricAttributionInput {
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn metric_attribution_arn(&self) -> ::std::option::Option<&str> {
        self.metric_attribution_arn.as_deref()
    }
}
impl DescribeMetricAttributionInput {
    /// Creates a new builder-style object to manufacture [`DescribeMetricAttributionInput`](crate::operation::describe_metric_attribution::DescribeMetricAttributionInput).
    pub fn builder() -> crate::operation::describe_metric_attribution::builders::DescribeMetricAttributionInputBuilder {
        crate::operation::describe_metric_attribution::builders::DescribeMetricAttributionInputBuilder::default()
    }
}

/// A builder for [`DescribeMetricAttributionInput`](crate::operation::describe_metric_attribution::DescribeMetricAttributionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMetricAttributionInputBuilder {
    pub(crate) metric_attribution_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeMetricAttributionInputBuilder {
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn metric_attribution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_attribution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn set_metric_attribution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_attribution_arn = input;
        self
    }
    /// <p>The metric attribution's Amazon Resource Name (ARN).</p>
    pub fn get_metric_attribution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_attribution_arn
    }
    /// Consumes the builder and constructs a [`DescribeMetricAttributionInput`](crate::operation::describe_metric_attribution::DescribeMetricAttributionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_metric_attribution::DescribeMetricAttributionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_metric_attribution::DescribeMetricAttributionInput {
            metric_attribution_arn: self.metric_attribution_arn,
        })
    }
}
