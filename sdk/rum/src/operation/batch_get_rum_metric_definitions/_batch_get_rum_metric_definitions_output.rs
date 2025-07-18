// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetRumMetricDefinitionsOutput {
    /// <p>An array of structures that display information about the metrics that are sent by the specified app monitor to the specified destination.</p>
    pub metric_definitions: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinition>>,
    /// <p>A token that you can use in a subsequent operation to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl BatchGetRumMetricDefinitionsOutput {
    /// <p>An array of structures that display information about the metrics that are sent by the specified app monitor to the specified destination.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_definitions.is_none()`.
    pub fn metric_definitions(&self) -> &[crate::types::MetricDefinition] {
        self.metric_definitions.as_deref().unwrap_or_default()
    }
    /// <p>A token that you can use in a subsequent operation to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetRumMetricDefinitionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetRumMetricDefinitionsOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetRumMetricDefinitionsOutput`](crate::operation::batch_get_rum_metric_definitions::BatchGetRumMetricDefinitionsOutput).
    pub fn builder() -> crate::operation::batch_get_rum_metric_definitions::builders::BatchGetRumMetricDefinitionsOutputBuilder {
        crate::operation::batch_get_rum_metric_definitions::builders::BatchGetRumMetricDefinitionsOutputBuilder::default()
    }
}

/// A builder for [`BatchGetRumMetricDefinitionsOutput`](crate::operation::batch_get_rum_metric_definitions::BatchGetRumMetricDefinitionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetRumMetricDefinitionsOutputBuilder {
    pub(crate) metric_definitions: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinition>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl BatchGetRumMetricDefinitionsOutputBuilder {
    /// Appends an item to `metric_definitions`.
    ///
    /// To override the contents of this collection use [`set_metric_definitions`](Self::set_metric_definitions).
    ///
    /// <p>An array of structures that display information about the metrics that are sent by the specified app monitor to the specified destination.</p>
    pub fn metric_definitions(mut self, input: crate::types::MetricDefinition) -> Self {
        let mut v = self.metric_definitions.unwrap_or_default();
        v.push(input);
        self.metric_definitions = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures that display information about the metrics that are sent by the specified app monitor to the specified destination.</p>
    pub fn set_metric_definitions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDefinition>>) -> Self {
        self.metric_definitions = input;
        self
    }
    /// <p>An array of structures that display information about the metrics that are sent by the specified app monitor to the specified destination.</p>
    pub fn get_metric_definitions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDefinition>> {
        &self.metric_definitions
    }
    /// <p>A token that you can use in a subsequent operation to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that you can use in a subsequent operation to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that you can use in a subsequent operation to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetRumMetricDefinitionsOutput`](crate::operation::batch_get_rum_metric_definitions::BatchGetRumMetricDefinitionsOutput).
    pub fn build(self) -> crate::operation::batch_get_rum_metric_definitions::BatchGetRumMetricDefinitionsOutput {
        crate::operation::batch_get_rum_metric_definitions::BatchGetRumMetricDefinitionsOutput {
            metric_definitions: self.metric_definitions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
