// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An anomaly detection model associated with a particular CloudWatch metric, statistic, or metric math expression. You can use the model to display a band of expected, normal values when the metric is graphed.</p>
/// <p>If you have enabled unified cross-account observability, and this account is a monitoring account, the metric can be in the same account or a source account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnomalyDetector {
    /// <p>The namespace of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Namespace property.")]
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.MetricName property.")]
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>The metric dimensions associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Dimensions property.")]
    pub dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
    /// <p>The statistic associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Stat property.")]
    pub stat: ::std::option::Option<::std::string::String>,
    /// <p>The configuration specifies details about how the anomaly detection model is to be trained, including time ranges to exclude from use for training the model, and the time zone to use for the metric.</p>
    pub configuration: ::std::option::Option<crate::types::AnomalyDetectorConfiguration>,
    /// <p>The current status of the anomaly detector's training.</p>
    pub state_value: ::std::option::Option<crate::types::AnomalyDetectorStateValue>,
    /// <p>This object includes parameters that you can use to provide information about your metric to CloudWatch to help it build more accurate anomaly detection models. Currently, it includes the <code>PeriodicSpikes</code> parameter.</p>
    pub metric_characteristics: ::std::option::Option<crate::types::MetricCharacteristics>,
    /// <p>The CloudWatch metric and statistic for this anomaly detector.</p>
    pub single_metric_anomaly_detector: ::std::option::Option<crate::types::SingleMetricAnomalyDetector>,
    /// <p>The CloudWatch metric math expression for this anomaly detector.</p>
    pub metric_math_anomaly_detector: ::std::option::Option<crate::types::MetricMathAnomalyDetector>,
}
impl AnomalyDetector {
    /// <p>The namespace of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Namespace property.")]
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.MetricName property.")]
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>The metric dimensions associated with the anomaly detection model.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dimensions.is_none()`.
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Dimensions property.")]
    pub fn dimensions(&self) -> &[crate::types::Dimension] {
        self.dimensions.as_deref().unwrap_or_default()
    }
    /// <p>The statistic associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Stat property.")]
    pub fn stat(&self) -> ::std::option::Option<&str> {
        self.stat.as_deref()
    }
    /// <p>The configuration specifies details about how the anomaly detection model is to be trained, including time ranges to exclude from use for training the model, and the time zone to use for the metric.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::AnomalyDetectorConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>The current status of the anomaly detector's training.</p>
    pub fn state_value(&self) -> ::std::option::Option<&crate::types::AnomalyDetectorStateValue> {
        self.state_value.as_ref()
    }
    /// <p>This object includes parameters that you can use to provide information about your metric to CloudWatch to help it build more accurate anomaly detection models. Currently, it includes the <code>PeriodicSpikes</code> parameter.</p>
    pub fn metric_characteristics(&self) -> ::std::option::Option<&crate::types::MetricCharacteristics> {
        self.metric_characteristics.as_ref()
    }
    /// <p>The CloudWatch metric and statistic for this anomaly detector.</p>
    pub fn single_metric_anomaly_detector(&self) -> ::std::option::Option<&crate::types::SingleMetricAnomalyDetector> {
        self.single_metric_anomaly_detector.as_ref()
    }
    /// <p>The CloudWatch metric math expression for this anomaly detector.</p>
    pub fn metric_math_anomaly_detector(&self) -> ::std::option::Option<&crate::types::MetricMathAnomalyDetector> {
        self.metric_math_anomaly_detector.as_ref()
    }
}
impl AnomalyDetector {
    /// Creates a new builder-style object to manufacture [`AnomalyDetector`](crate::types::AnomalyDetector).
    pub fn builder() -> crate::types::builders::AnomalyDetectorBuilder {
        crate::types::builders::AnomalyDetectorBuilder::default()
    }
}

/// A builder for [`AnomalyDetector`](crate::types::AnomalyDetector).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnomalyDetectorBuilder {
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
    pub(crate) stat: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::AnomalyDetectorConfiguration>,
    pub(crate) state_value: ::std::option::Option<crate::types::AnomalyDetectorStateValue>,
    pub(crate) metric_characteristics: ::std::option::Option<crate::types::MetricCharacteristics>,
    pub(crate) single_metric_anomaly_detector: ::std::option::Option<crate::types::SingleMetricAnomalyDetector>,
    pub(crate) metric_math_anomaly_detector: ::std::option::Option<crate::types::MetricMathAnomalyDetector>,
}
impl AnomalyDetectorBuilder {
    /// <p>The namespace of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Namespace property.")]
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Namespace property.")]
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Namespace property.")]
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The name of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.MetricName property.")]
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.MetricName property.")]
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the metric associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.MetricName property.")]
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>The metric dimensions associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Dimensions property.")]
    pub fn dimensions(mut self, input: crate::types::Dimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The metric dimensions associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Dimensions property.")]
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>The metric dimensions associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Dimensions property.")]
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Dimension>> {
        &self.dimensions
    }
    /// <p>The statistic associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Stat property.")]
    pub fn stat(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stat = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The statistic associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Stat property.")]
    pub fn set_stat(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stat = input;
        self
    }
    /// <p>The statistic associated with the anomaly detection model.</p>
    #[deprecated(note = "Use SingleMetricAnomalyDetector.Stat property.")]
    pub fn get_stat(&self) -> &::std::option::Option<::std::string::String> {
        &self.stat
    }
    /// <p>The configuration specifies details about how the anomaly detection model is to be trained, including time ranges to exclude from use for training the model, and the time zone to use for the metric.</p>
    pub fn configuration(mut self, input: crate::types::AnomalyDetectorConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration specifies details about how the anomaly detection model is to be trained, including time ranges to exclude from use for training the model, and the time zone to use for the metric.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::AnomalyDetectorConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The configuration specifies details about how the anomaly detection model is to be trained, including time ranges to exclude from use for training the model, and the time zone to use for the metric.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::AnomalyDetectorConfiguration> {
        &self.configuration
    }
    /// <p>The current status of the anomaly detector's training.</p>
    pub fn state_value(mut self, input: crate::types::AnomalyDetectorStateValue) -> Self {
        self.state_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the anomaly detector's training.</p>
    pub fn set_state_value(mut self, input: ::std::option::Option<crate::types::AnomalyDetectorStateValue>) -> Self {
        self.state_value = input;
        self
    }
    /// <p>The current status of the anomaly detector's training.</p>
    pub fn get_state_value(&self) -> &::std::option::Option<crate::types::AnomalyDetectorStateValue> {
        &self.state_value
    }
    /// <p>This object includes parameters that you can use to provide information about your metric to CloudWatch to help it build more accurate anomaly detection models. Currently, it includes the <code>PeriodicSpikes</code> parameter.</p>
    pub fn metric_characteristics(mut self, input: crate::types::MetricCharacteristics) -> Self {
        self.metric_characteristics = ::std::option::Option::Some(input);
        self
    }
    /// <p>This object includes parameters that you can use to provide information about your metric to CloudWatch to help it build more accurate anomaly detection models. Currently, it includes the <code>PeriodicSpikes</code> parameter.</p>
    pub fn set_metric_characteristics(mut self, input: ::std::option::Option<crate::types::MetricCharacteristics>) -> Self {
        self.metric_characteristics = input;
        self
    }
    /// <p>This object includes parameters that you can use to provide information about your metric to CloudWatch to help it build more accurate anomaly detection models. Currently, it includes the <code>PeriodicSpikes</code> parameter.</p>
    pub fn get_metric_characteristics(&self) -> &::std::option::Option<crate::types::MetricCharacteristics> {
        &self.metric_characteristics
    }
    /// <p>The CloudWatch metric and statistic for this anomaly detector.</p>
    pub fn single_metric_anomaly_detector(mut self, input: crate::types::SingleMetricAnomalyDetector) -> Self {
        self.single_metric_anomaly_detector = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CloudWatch metric and statistic for this anomaly detector.</p>
    pub fn set_single_metric_anomaly_detector(mut self, input: ::std::option::Option<crate::types::SingleMetricAnomalyDetector>) -> Self {
        self.single_metric_anomaly_detector = input;
        self
    }
    /// <p>The CloudWatch metric and statistic for this anomaly detector.</p>
    pub fn get_single_metric_anomaly_detector(&self) -> &::std::option::Option<crate::types::SingleMetricAnomalyDetector> {
        &self.single_metric_anomaly_detector
    }
    /// <p>The CloudWatch metric math expression for this anomaly detector.</p>
    pub fn metric_math_anomaly_detector(mut self, input: crate::types::MetricMathAnomalyDetector) -> Self {
        self.metric_math_anomaly_detector = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CloudWatch metric math expression for this anomaly detector.</p>
    pub fn set_metric_math_anomaly_detector(mut self, input: ::std::option::Option<crate::types::MetricMathAnomalyDetector>) -> Self {
        self.metric_math_anomaly_detector = input;
        self
    }
    /// <p>The CloudWatch metric math expression for this anomaly detector.</p>
    pub fn get_metric_math_anomaly_detector(&self) -> &::std::option::Option<crate::types::MetricMathAnomalyDetector> {
        &self.metric_math_anomaly_detector
    }
    /// Consumes the builder and constructs a [`AnomalyDetector`](crate::types::AnomalyDetector).
    pub fn build(self) -> crate::types::AnomalyDetector {
        crate::types::AnomalyDetector {
            namespace: self.namespace,
            metric_name: self.metric_name,
            dimensions: self.dimensions,
            stat: self.stat,
            configuration: self.configuration,
            state_value: self.state_value,
            metric_characteristics: self.metric_characteristics,
            single_metric_anomaly_detector: self.single_metric_anomaly_detector,
            metric_math_anomaly_detector: self.metric_math_anomaly_detector,
        }
    }
}
