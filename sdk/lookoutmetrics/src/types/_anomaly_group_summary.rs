// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a group of anomalous metrics.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnomalyGroupSummary {
    /// <p>The start time for the group.</p>
    pub start_time: ::std::option::Option<::std::string::String>,
    /// <p>The end time for the group.</p>
    pub end_time: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the anomaly group.</p>
    pub anomaly_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The severity score of the group.</p>
    pub anomaly_group_score: ::std::option::Option<f64>,
    /// <p>The name of the primary affected measure for the group.</p>
    pub primary_metric_name: ::std::option::Option<::std::string::String>,
}
impl AnomalyGroupSummary {
    /// <p>The start time for the group.</p>
    pub fn start_time(&self) -> ::std::option::Option<&str> {
        self.start_time.as_deref()
    }
    /// <p>The end time for the group.</p>
    pub fn end_time(&self) -> ::std::option::Option<&str> {
        self.end_time.as_deref()
    }
    /// <p>The ID of the anomaly group.</p>
    pub fn anomaly_group_id(&self) -> ::std::option::Option<&str> {
        self.anomaly_group_id.as_deref()
    }
    /// <p>The severity score of the group.</p>
    pub fn anomaly_group_score(&self) -> ::std::option::Option<f64> {
        self.anomaly_group_score
    }
    /// <p>The name of the primary affected measure for the group.</p>
    pub fn primary_metric_name(&self) -> ::std::option::Option<&str> {
        self.primary_metric_name.as_deref()
    }
}
impl AnomalyGroupSummary {
    /// Creates a new builder-style object to manufacture [`AnomalyGroupSummary`](crate::types::AnomalyGroupSummary).
    pub fn builder() -> crate::types::builders::AnomalyGroupSummaryBuilder {
        crate::types::builders::AnomalyGroupSummaryBuilder::default()
    }
}

/// A builder for [`AnomalyGroupSummary`](crate::types::AnomalyGroupSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnomalyGroupSummaryBuilder {
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
    pub(crate) end_time: ::std::option::Option<::std::string::String>,
    pub(crate) anomaly_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) anomaly_group_score: ::std::option::Option<f64>,
    pub(crate) primary_metric_name: ::std::option::Option<::std::string::String>,
}
impl AnomalyGroupSummaryBuilder {
    /// <p>The start time for the group.</p>
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The start time for the group.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time for the group.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// <p>The end time for the group.</p>
    pub fn end_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The end time for the group.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time for the group.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_time
    }
    /// <p>The ID of the anomaly group.</p>
    pub fn anomaly_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the anomaly group.</p>
    pub fn set_anomaly_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_group_id = input;
        self
    }
    /// <p>The ID of the anomaly group.</p>
    pub fn get_anomaly_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_group_id
    }
    /// <p>The severity score of the group.</p>
    pub fn anomaly_group_score(mut self, input: f64) -> Self {
        self.anomaly_group_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The severity score of the group.</p>
    pub fn set_anomaly_group_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.anomaly_group_score = input;
        self
    }
    /// <p>The severity score of the group.</p>
    pub fn get_anomaly_group_score(&self) -> &::std::option::Option<f64> {
        &self.anomaly_group_score
    }
    /// <p>The name of the primary affected measure for the group.</p>
    pub fn primary_metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the primary affected measure for the group.</p>
    pub fn set_primary_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_metric_name = input;
        self
    }
    /// <p>The name of the primary affected measure for the group.</p>
    pub fn get_primary_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_metric_name
    }
    /// Consumes the builder and constructs a [`AnomalyGroupSummary`](crate::types::AnomalyGroupSummary).
    pub fn build(self) -> crate::types::AnomalyGroupSummary {
        crate::types::AnomalyGroupSummary {
            start_time: self.start_time,
            end_time: self.end_time,
            anomaly_group_id: self.anomaly_group_id,
            anomaly_group_score: self.anomaly_group_score,
            primary_metric_name: self.primary_metric_name,
        }
    }
}
