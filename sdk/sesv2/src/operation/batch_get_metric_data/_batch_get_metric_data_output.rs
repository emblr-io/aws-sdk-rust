// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the result of processing your metric data batch request</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetMetricDataOutput {
    /// <p>A list of successfully retrieved <code>MetricDataResult</code>.</p>
    pub results: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataResult>>,
    /// <p>A list of <code>MetricDataError</code> encountered while processing your metric data batch request.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataError>>,
    _request_id: Option<String>,
}
impl BatchGetMetricDataOutput {
    /// <p>A list of successfully retrieved <code>MetricDataResult</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.results.is_none()`.
    pub fn results(&self) -> &[crate::types::MetricDataResult] {
        self.results.as_deref().unwrap_or_default()
    }
    /// <p>A list of <code>MetricDataError</code> encountered while processing your metric data batch request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::MetricDataError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetMetricDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetMetricDataOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetMetricDataOutput`](crate::operation::batch_get_metric_data::BatchGetMetricDataOutput).
    pub fn builder() -> crate::operation::batch_get_metric_data::builders::BatchGetMetricDataOutputBuilder {
        crate::operation::batch_get_metric_data::builders::BatchGetMetricDataOutputBuilder::default()
    }
}

/// A builder for [`BatchGetMetricDataOutput`](crate::operation::batch_get_metric_data::BatchGetMetricDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetMetricDataOutputBuilder {
    pub(crate) results: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataResult>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataError>>,
    _request_id: Option<String>,
}
impl BatchGetMetricDataOutputBuilder {
    /// Appends an item to `results`.
    ///
    /// To override the contents of this collection use [`set_results`](Self::set_results).
    ///
    /// <p>A list of successfully retrieved <code>MetricDataResult</code>.</p>
    pub fn results(mut self, input: crate::types::MetricDataResult) -> Self {
        let mut v = self.results.unwrap_or_default();
        v.push(input);
        self.results = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of successfully retrieved <code>MetricDataResult</code>.</p>
    pub fn set_results(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataResult>>) -> Self {
        self.results = input;
        self
    }
    /// <p>A list of successfully retrieved <code>MetricDataResult</code>.</p>
    pub fn get_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDataResult>> {
        &self.results
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>A list of <code>MetricDataError</code> encountered while processing your metric data batch request.</p>
    pub fn errors(mut self, input: crate::types::MetricDataError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>MetricDataError</code> encountered while processing your metric data batch request.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>A list of <code>MetricDataError</code> encountered while processing your metric data batch request.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDataError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetMetricDataOutput`](crate::operation::batch_get_metric_data::BatchGetMetricDataOutput).
    pub fn build(self) -> crate::operation::batch_get_metric_data::BatchGetMetricDataOutput {
        crate::operation::batch_get_metric_data::BatchGetMetricDataOutput {
            results: self.results,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
