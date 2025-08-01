// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object containing the results for the intent metric you requested.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyticsIntentMetricResult {
    /// <p>The metric that you requested. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/analytics-key-definitions.html">Key definitions</a> for more details about these metrics.</p>
    /// <ul>
    /// <li>
    /// <p><code>Count</code> – The number of times the intent was invoked.</p></li>
    /// <li>
    /// <p><code>Success</code> – The number of times the intent succeeded.</p></li>
    /// <li>
    /// <p><code>Failure</code> – The number of times the intent failed.</p></li>
    /// <li>
    /// <p><code>Switched</code> – The number of times there was a switch to a different intent.</p></li>
    /// <li>
    /// <p><code>Dropped</code> – The number of times the user dropped the intent.</p></li>
    /// </ul>
    pub name: ::std::option::Option<crate::types::AnalyticsIntentMetricName>,
    /// <p>The statistic that you requested to calculate.</p>
    /// <ul>
    /// <li>
    /// <p><code>Sum</code> – The total count for the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Average</code> – The total count divided by the number of intents in the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Max</code> – The highest count in the category you provide in <code>name</code>.</p></li>
    /// </ul>
    pub statistic: ::std::option::Option<crate::types::AnalyticsMetricStatistic>,
    /// <p>The value of the summary statistic for the metric that you requested.</p>
    pub value: ::std::option::Option<f64>,
}
impl AnalyticsIntentMetricResult {
    /// <p>The metric that you requested. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/analytics-key-definitions.html">Key definitions</a> for more details about these metrics.</p>
    /// <ul>
    /// <li>
    /// <p><code>Count</code> – The number of times the intent was invoked.</p></li>
    /// <li>
    /// <p><code>Success</code> – The number of times the intent succeeded.</p></li>
    /// <li>
    /// <p><code>Failure</code> – The number of times the intent failed.</p></li>
    /// <li>
    /// <p><code>Switched</code> – The number of times there was a switch to a different intent.</p></li>
    /// <li>
    /// <p><code>Dropped</code> – The number of times the user dropped the intent.</p></li>
    /// </ul>
    pub fn name(&self) -> ::std::option::Option<&crate::types::AnalyticsIntentMetricName> {
        self.name.as_ref()
    }
    /// <p>The statistic that you requested to calculate.</p>
    /// <ul>
    /// <li>
    /// <p><code>Sum</code> – The total count for the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Average</code> – The total count divided by the number of intents in the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Max</code> – The highest count in the category you provide in <code>name</code>.</p></li>
    /// </ul>
    pub fn statistic(&self) -> ::std::option::Option<&crate::types::AnalyticsMetricStatistic> {
        self.statistic.as_ref()
    }
    /// <p>The value of the summary statistic for the metric that you requested.</p>
    pub fn value(&self) -> ::std::option::Option<f64> {
        self.value
    }
}
impl AnalyticsIntentMetricResult {
    /// Creates a new builder-style object to manufacture [`AnalyticsIntentMetricResult`](crate::types::AnalyticsIntentMetricResult).
    pub fn builder() -> crate::types::builders::AnalyticsIntentMetricResultBuilder {
        crate::types::builders::AnalyticsIntentMetricResultBuilder::default()
    }
}

/// A builder for [`AnalyticsIntentMetricResult`](crate::types::AnalyticsIntentMetricResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyticsIntentMetricResultBuilder {
    pub(crate) name: ::std::option::Option<crate::types::AnalyticsIntentMetricName>,
    pub(crate) statistic: ::std::option::Option<crate::types::AnalyticsMetricStatistic>,
    pub(crate) value: ::std::option::Option<f64>,
}
impl AnalyticsIntentMetricResultBuilder {
    /// <p>The metric that you requested. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/analytics-key-definitions.html">Key definitions</a> for more details about these metrics.</p>
    /// <ul>
    /// <li>
    /// <p><code>Count</code> – The number of times the intent was invoked.</p></li>
    /// <li>
    /// <p><code>Success</code> – The number of times the intent succeeded.</p></li>
    /// <li>
    /// <p><code>Failure</code> – The number of times the intent failed.</p></li>
    /// <li>
    /// <p><code>Switched</code> – The number of times there was a switch to a different intent.</p></li>
    /// <li>
    /// <p><code>Dropped</code> – The number of times the user dropped the intent.</p></li>
    /// </ul>
    pub fn name(mut self, input: crate::types::AnalyticsIntentMetricName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric that you requested. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/analytics-key-definitions.html">Key definitions</a> for more details about these metrics.</p>
    /// <ul>
    /// <li>
    /// <p><code>Count</code> – The number of times the intent was invoked.</p></li>
    /// <li>
    /// <p><code>Success</code> – The number of times the intent succeeded.</p></li>
    /// <li>
    /// <p><code>Failure</code> – The number of times the intent failed.</p></li>
    /// <li>
    /// <p><code>Switched</code> – The number of times there was a switch to a different intent.</p></li>
    /// <li>
    /// <p><code>Dropped</code> – The number of times the user dropped the intent.</p></li>
    /// </ul>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::AnalyticsIntentMetricName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The metric that you requested. See <a href="https://docs.aws.amazon.com/lexv2/latest/dg/analytics-key-definitions.html">Key definitions</a> for more details about these metrics.</p>
    /// <ul>
    /// <li>
    /// <p><code>Count</code> – The number of times the intent was invoked.</p></li>
    /// <li>
    /// <p><code>Success</code> – The number of times the intent succeeded.</p></li>
    /// <li>
    /// <p><code>Failure</code> – The number of times the intent failed.</p></li>
    /// <li>
    /// <p><code>Switched</code> – The number of times there was a switch to a different intent.</p></li>
    /// <li>
    /// <p><code>Dropped</code> – The number of times the user dropped the intent.</p></li>
    /// </ul>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::AnalyticsIntentMetricName> {
        &self.name
    }
    /// <p>The statistic that you requested to calculate.</p>
    /// <ul>
    /// <li>
    /// <p><code>Sum</code> – The total count for the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Average</code> – The total count divided by the number of intents in the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Max</code> – The highest count in the category you provide in <code>name</code>.</p></li>
    /// </ul>
    pub fn statistic(mut self, input: crate::types::AnalyticsMetricStatistic) -> Self {
        self.statistic = ::std::option::Option::Some(input);
        self
    }
    /// <p>The statistic that you requested to calculate.</p>
    /// <ul>
    /// <li>
    /// <p><code>Sum</code> – The total count for the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Average</code> – The total count divided by the number of intents in the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Max</code> – The highest count in the category you provide in <code>name</code>.</p></li>
    /// </ul>
    pub fn set_statistic(mut self, input: ::std::option::Option<crate::types::AnalyticsMetricStatistic>) -> Self {
        self.statistic = input;
        self
    }
    /// <p>The statistic that you requested to calculate.</p>
    /// <ul>
    /// <li>
    /// <p><code>Sum</code> – The total count for the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Average</code> – The total count divided by the number of intents in the category you provide in <code>name</code>.</p></li>
    /// <li>
    /// <p><code>Max</code> – The highest count in the category you provide in <code>name</code>.</p></li>
    /// </ul>
    pub fn get_statistic(&self) -> &::std::option::Option<crate::types::AnalyticsMetricStatistic> {
        &self.statistic
    }
    /// <p>The value of the summary statistic for the metric that you requested.</p>
    pub fn value(mut self, input: f64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the summary statistic for the metric that you requested.</p>
    pub fn set_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the summary statistic for the metric that you requested.</p>
    pub fn get_value(&self) -> &::std::option::Option<f64> {
        &self.value
    }
    /// Consumes the builder and constructs a [`AnalyticsIntentMetricResult`](crate::types::AnalyticsIntentMetricResult).
    pub fn build(self) -> crate::types::AnalyticsIntentMetricResult {
        crate::types::AnalyticsIntentMetricResult {
            name: self.name,
            statistic: self.statistic,
            value: self.value,
        }
    }
}
