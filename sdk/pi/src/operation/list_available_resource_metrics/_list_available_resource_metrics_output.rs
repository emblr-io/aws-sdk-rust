// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAvailableResourceMetricsOutput {
    /// <p>An array of metrics available to query. Each array element contains the full name, description, and unit of the metric.</p>
    pub metrics: ::std::option::Option<::std::vec::Vec<crate::types::ResponseResourceMetric>>,
    /// <p>A pagination token that indicates the response didn’t return all available records because <code>MaxRecords</code> was specified in the previous request. To get the remaining records, specify <code>NextToken</code> in a separate request with this value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAvailableResourceMetricsOutput {
    /// <p>An array of metrics available to query. Each array element contains the full name, description, and unit of the metric.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metrics.is_none()`.
    pub fn metrics(&self) -> &[crate::types::ResponseResourceMetric] {
        self.metrics.as_deref().unwrap_or_default()
    }
    /// <p>A pagination token that indicates the response didn’t return all available records because <code>MaxRecords</code> was specified in the previous request. To get the remaining records, specify <code>NextToken</code> in a separate request with this value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAvailableResourceMetricsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAvailableResourceMetricsOutput {
    /// Creates a new builder-style object to manufacture [`ListAvailableResourceMetricsOutput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsOutput).
    pub fn builder() -> crate::operation::list_available_resource_metrics::builders::ListAvailableResourceMetricsOutputBuilder {
        crate::operation::list_available_resource_metrics::builders::ListAvailableResourceMetricsOutputBuilder::default()
    }
}

/// A builder for [`ListAvailableResourceMetricsOutput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAvailableResourceMetricsOutputBuilder {
    pub(crate) metrics: ::std::option::Option<::std::vec::Vec<crate::types::ResponseResourceMetric>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAvailableResourceMetricsOutputBuilder {
    /// Appends an item to `metrics`.
    ///
    /// To override the contents of this collection use [`set_metrics`](Self::set_metrics).
    ///
    /// <p>An array of metrics available to query. Each array element contains the full name, description, and unit of the metric.</p>
    pub fn metrics(mut self, input: crate::types::ResponseResourceMetric) -> Self {
        let mut v = self.metrics.unwrap_or_default();
        v.push(input);
        self.metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of metrics available to query. Each array element contains the full name, description, and unit of the metric.</p>
    pub fn set_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResponseResourceMetric>>) -> Self {
        self.metrics = input;
        self
    }
    /// <p>An array of metrics available to query. Each array element contains the full name, description, and unit of the metric.</p>
    pub fn get_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResponseResourceMetric>> {
        &self.metrics
    }
    /// <p>A pagination token that indicates the response didn’t return all available records because <code>MaxRecords</code> was specified in the previous request. To get the remaining records, specify <code>NextToken</code> in a separate request with this value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token that indicates the response didn’t return all available records because <code>MaxRecords</code> was specified in the previous request. To get the remaining records, specify <code>NextToken</code> in a separate request with this value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token that indicates the response didn’t return all available records because <code>MaxRecords</code> was specified in the previous request. To get the remaining records, specify <code>NextToken</code> in a separate request with this value.</p>
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
    /// Consumes the builder and constructs a [`ListAvailableResourceMetricsOutput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsOutput).
    pub fn build(self) -> crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsOutput {
        crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsOutput {
            metrics: self.metrics,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
