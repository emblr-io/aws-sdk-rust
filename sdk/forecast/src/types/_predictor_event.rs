// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about a predictor event, such as a retraining.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PredictorEvent {
    /// <p>The type of event. For example, <code>Retrain</code>. A retraining event denotes the timepoint when a predictor was retrained. Any monitor results from before the <code>Datetime</code> are from the previous predictor. Any new metrics are for the newly retrained predictor.</p>
    pub detail: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp for when the event occurred.</p>
    pub datetime: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PredictorEvent {
    /// <p>The type of event. For example, <code>Retrain</code>. A retraining event denotes the timepoint when a predictor was retrained. Any monitor results from before the <code>Datetime</code> are from the previous predictor. Any new metrics are for the newly retrained predictor.</p>
    pub fn detail(&self) -> ::std::option::Option<&str> {
        self.detail.as_deref()
    }
    /// <p>The timestamp for when the event occurred.</p>
    pub fn datetime(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.datetime.as_ref()
    }
}
impl PredictorEvent {
    /// Creates a new builder-style object to manufacture [`PredictorEvent`](crate::types::PredictorEvent).
    pub fn builder() -> crate::types::builders::PredictorEventBuilder {
        crate::types::builders::PredictorEventBuilder::default()
    }
}

/// A builder for [`PredictorEvent`](crate::types::PredictorEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PredictorEventBuilder {
    pub(crate) detail: ::std::option::Option<::std::string::String>,
    pub(crate) datetime: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PredictorEventBuilder {
    /// <p>The type of event. For example, <code>Retrain</code>. A retraining event denotes the timepoint when a predictor was retrained. Any monitor results from before the <code>Datetime</code> are from the previous predictor. Any new metrics are for the newly retrained predictor.</p>
    pub fn detail(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detail = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of event. For example, <code>Retrain</code>. A retraining event denotes the timepoint when a predictor was retrained. Any monitor results from before the <code>Datetime</code> are from the previous predictor. Any new metrics are for the newly retrained predictor.</p>
    pub fn set_detail(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detail = input;
        self
    }
    /// <p>The type of event. For example, <code>Retrain</code>. A retraining event denotes the timepoint when a predictor was retrained. Any monitor results from before the <code>Datetime</code> are from the previous predictor. Any new metrics are for the newly retrained predictor.</p>
    pub fn get_detail(&self) -> &::std::option::Option<::std::string::String> {
        &self.detail
    }
    /// <p>The timestamp for when the event occurred.</p>
    pub fn datetime(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.datetime = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the event occurred.</p>
    pub fn set_datetime(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.datetime = input;
        self
    }
    /// <p>The timestamp for when the event occurred.</p>
    pub fn get_datetime(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.datetime
    }
    /// Consumes the builder and constructs a [`PredictorEvent`](crate::types::PredictorEvent).
    pub fn build(self) -> crate::types::PredictorEvent {
        crate::types::PredictorEvent {
            detail: self.detail,
            datetime: self.datetime,
        }
    }
}
