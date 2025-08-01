// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains an asset metric property. With metrics, you can calculate aggregate functions, such as an average, maximum, or minimum, as specified through an expression. A metric maps several values to a single value (such as a sum).</p>
/// <p>The maximum number of dependent/cascading variables used in any one metric calculation is 10. Therefore, a <i>root</i> metric can have up to 10 cascading metrics in its computational dependency tree. Additionally, a metric can only have a data type of <code>DOUBLE</code> and consume properties with data types of <code>INTEGER</code> or <code>DOUBLE</code>.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/asset-properties.html#metrics">Metrics</a> in the <i>IoT SiteWise User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Metric {
    /// <p>The mathematical expression that defines the metric aggregation function. You can specify up to 10 variables per expression. You can specify up to 10 functions per expression.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/quotas.html">Quotas</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub expression: ::std::string::String,
    /// <p>The list of variables used in the expression.</p>
    pub variables: ::std::vec::Vec<crate::types::ExpressionVariable>,
    /// <p>The window (time interval) over which IoT SiteWise computes the metric's aggregation expression. IoT SiteWise computes one data point per <code>window</code>.</p>
    pub window: ::std::option::Option<crate::types::MetricWindow>,
    /// <p>The processing configuration for the given metric property. You can configure metrics to be computed at the edge or in the Amazon Web Services Cloud. By default, metrics are forwarded to the cloud.</p>
    pub processing_config: ::std::option::Option<crate::types::MetricProcessingConfig>,
}
impl Metric {
    /// <p>The mathematical expression that defines the metric aggregation function. You can specify up to 10 variables per expression. You can specify up to 10 functions per expression.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/quotas.html">Quotas</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn expression(&self) -> &str {
        use std::ops::Deref;
        self.expression.deref()
    }
    /// <p>The list of variables used in the expression.</p>
    pub fn variables(&self) -> &[crate::types::ExpressionVariable] {
        use std::ops::Deref;
        self.variables.deref()
    }
    /// <p>The window (time interval) over which IoT SiteWise computes the metric's aggregation expression. IoT SiteWise computes one data point per <code>window</code>.</p>
    pub fn window(&self) -> ::std::option::Option<&crate::types::MetricWindow> {
        self.window.as_ref()
    }
    /// <p>The processing configuration for the given metric property. You can configure metrics to be computed at the edge or in the Amazon Web Services Cloud. By default, metrics are forwarded to the cloud.</p>
    pub fn processing_config(&self) -> ::std::option::Option<&crate::types::MetricProcessingConfig> {
        self.processing_config.as_ref()
    }
}
impl Metric {
    /// Creates a new builder-style object to manufacture [`Metric`](crate::types::Metric).
    pub fn builder() -> crate::types::builders::MetricBuilder {
        crate::types::builders::MetricBuilder::default()
    }
}

/// A builder for [`Metric`](crate::types::Metric).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricBuilder {
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) variables: ::std::option::Option<::std::vec::Vec<crate::types::ExpressionVariable>>,
    pub(crate) window: ::std::option::Option<crate::types::MetricWindow>,
    pub(crate) processing_config: ::std::option::Option<crate::types::MetricProcessingConfig>,
}
impl MetricBuilder {
    /// <p>The mathematical expression that defines the metric aggregation function. You can specify up to 10 variables per expression. You can specify up to 10 functions per expression.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/quotas.html">Quotas</a> in the <i>IoT SiteWise User Guide</i>.</p>
    /// This field is required.
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The mathematical expression that defines the metric aggregation function. You can specify up to 10 variables per expression. You can specify up to 10 functions per expression.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/quotas.html">Quotas</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>The mathematical expression that defines the metric aggregation function. You can specify up to 10 variables per expression. You can specify up to 10 functions per expression.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/quotas.html">Quotas</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// Appends an item to `variables`.
    ///
    /// To override the contents of this collection use [`set_variables`](Self::set_variables).
    ///
    /// <p>The list of variables used in the expression.</p>
    pub fn variables(mut self, input: crate::types::ExpressionVariable) -> Self {
        let mut v = self.variables.unwrap_or_default();
        v.push(input);
        self.variables = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of variables used in the expression.</p>
    pub fn set_variables(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExpressionVariable>>) -> Self {
        self.variables = input;
        self
    }
    /// <p>The list of variables used in the expression.</p>
    pub fn get_variables(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExpressionVariable>> {
        &self.variables
    }
    /// <p>The window (time interval) over which IoT SiteWise computes the metric's aggregation expression. IoT SiteWise computes one data point per <code>window</code>.</p>
    /// This field is required.
    pub fn window(mut self, input: crate::types::MetricWindow) -> Self {
        self.window = ::std::option::Option::Some(input);
        self
    }
    /// <p>The window (time interval) over which IoT SiteWise computes the metric's aggregation expression. IoT SiteWise computes one data point per <code>window</code>.</p>
    pub fn set_window(mut self, input: ::std::option::Option<crate::types::MetricWindow>) -> Self {
        self.window = input;
        self
    }
    /// <p>The window (time interval) over which IoT SiteWise computes the metric's aggregation expression. IoT SiteWise computes one data point per <code>window</code>.</p>
    pub fn get_window(&self) -> &::std::option::Option<crate::types::MetricWindow> {
        &self.window
    }
    /// <p>The processing configuration for the given metric property. You can configure metrics to be computed at the edge or in the Amazon Web Services Cloud. By default, metrics are forwarded to the cloud.</p>
    pub fn processing_config(mut self, input: crate::types::MetricProcessingConfig) -> Self {
        self.processing_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The processing configuration for the given metric property. You can configure metrics to be computed at the edge or in the Amazon Web Services Cloud. By default, metrics are forwarded to the cloud.</p>
    pub fn set_processing_config(mut self, input: ::std::option::Option<crate::types::MetricProcessingConfig>) -> Self {
        self.processing_config = input;
        self
    }
    /// <p>The processing configuration for the given metric property. You can configure metrics to be computed at the edge or in the Amazon Web Services Cloud. By default, metrics are forwarded to the cloud.</p>
    pub fn get_processing_config(&self) -> &::std::option::Option<crate::types::MetricProcessingConfig> {
        &self.processing_config
    }
    /// Consumes the builder and constructs a [`Metric`](crate::types::Metric).
    /// This method will fail if any of the following fields are not set:
    /// - [`expression`](crate::types::builders::MetricBuilder::expression)
    /// - [`variables`](crate::types::builders::MetricBuilder::variables)
    pub fn build(self) -> ::std::result::Result<crate::types::Metric, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Metric {
            expression: self.expression.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expression",
                    "expression was not specified but it is required when building Metric",
                )
            })?,
            variables: self.variables.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "variables",
                    "variables was not specified but it is required when building Metric",
                )
            })?,
            window: self.window,
            processing_config: self.processing_config,
        })
    }
}
