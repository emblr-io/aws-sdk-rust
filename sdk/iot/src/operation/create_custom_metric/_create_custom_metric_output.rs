// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCustomMetricOutput {
    /// <p>The name of the custom metric to be used in the metric report.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Number (ARN) of the custom metric. For example, <code>arn:<i>aws-partition</i>:iot:<i>region</i>:<i>accountId</i>:custommetric/<i>metricName</i> </code></p>
    pub metric_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCustomMetricOutput {
    /// <p>The name of the custom metric to be used in the metric report.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>The Amazon Resource Number (ARN) of the custom metric. For example, <code>arn:<i>aws-partition</i>:iot:<i>region</i>:<i>accountId</i>:custommetric/<i>metricName</i> </code></p>
    pub fn metric_arn(&self) -> ::std::option::Option<&str> {
        self.metric_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCustomMetricOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCustomMetricOutput {
    /// Creates a new builder-style object to manufacture [`CreateCustomMetricOutput`](crate::operation::create_custom_metric::CreateCustomMetricOutput).
    pub fn builder() -> crate::operation::create_custom_metric::builders::CreateCustomMetricOutputBuilder {
        crate::operation::create_custom_metric::builders::CreateCustomMetricOutputBuilder::default()
    }
}

/// A builder for [`CreateCustomMetricOutput`](crate::operation::create_custom_metric::CreateCustomMetricOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCustomMetricOutputBuilder {
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) metric_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCustomMetricOutputBuilder {
    /// <p>The name of the custom metric to be used in the metric report.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom metric to be used in the metric report.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the custom metric to be used in the metric report.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// <p>The Amazon Resource Number (ARN) of the custom metric. For example, <code>arn:<i>aws-partition</i>:iot:<i>region</i>:<i>accountId</i>:custommetric/<i>metricName</i> </code></p>
    pub fn metric_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the custom metric. For example, <code>arn:<i>aws-partition</i>:iot:<i>region</i>:<i>accountId</i>:custommetric/<i>metricName</i> </code></p>
    pub fn set_metric_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the custom metric. For example, <code>arn:<i>aws-partition</i>:iot:<i>region</i>:<i>accountId</i>:custommetric/<i>metricName</i> </code></p>
    pub fn get_metric_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCustomMetricOutput`](crate::operation::create_custom_metric::CreateCustomMetricOutput).
    pub fn build(self) -> crate::operation::create_custom_metric::CreateCustomMetricOutput {
        crate::operation::create_custom_metric::CreateCustomMetricOutput {
            metric_name: self.metric_name,
            metric_arn: self.metric_arn,
            _request_id: self._request_id,
        }
    }
}
