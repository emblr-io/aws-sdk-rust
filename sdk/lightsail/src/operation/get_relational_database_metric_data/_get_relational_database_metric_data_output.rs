// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabaseMetricDataOutput {
    /// <p>The name of the metric returned.</p>
    pub metric_name: ::std::option::Option<crate::types::RelationalDatabaseMetricName>,
    /// <p>An array of objects that describe the metric data returned.</p>
    pub metric_data: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatapoint>>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseMetricDataOutput {
    /// <p>The name of the metric returned.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&crate::types::RelationalDatabaseMetricName> {
        self.metric_name.as_ref()
    }
    /// <p>An array of objects that describe the metric data returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_data.is_none()`.
    pub fn metric_data(&self) -> &[crate::types::MetricDatapoint] {
        self.metric_data.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetRelationalDatabaseMetricDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRelationalDatabaseMetricDataOutput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabaseMetricDataOutput`](crate::operation::get_relational_database_metric_data::GetRelationalDatabaseMetricDataOutput).
    pub fn builder() -> crate::operation::get_relational_database_metric_data::builders::GetRelationalDatabaseMetricDataOutputBuilder {
        crate::operation::get_relational_database_metric_data::builders::GetRelationalDatabaseMetricDataOutputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabaseMetricDataOutput`](crate::operation::get_relational_database_metric_data::GetRelationalDatabaseMetricDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabaseMetricDataOutputBuilder {
    pub(crate) metric_name: ::std::option::Option<crate::types::RelationalDatabaseMetricName>,
    pub(crate) metric_data: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatapoint>>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseMetricDataOutputBuilder {
    /// <p>The name of the metric returned.</p>
    pub fn metric_name(mut self, input: crate::types::RelationalDatabaseMetricName) -> Self {
        self.metric_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the metric returned.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<crate::types::RelationalDatabaseMetricName>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the metric returned.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<crate::types::RelationalDatabaseMetricName> {
        &self.metric_name
    }
    /// Appends an item to `metric_data`.
    ///
    /// To override the contents of this collection use [`set_metric_data`](Self::set_metric_data).
    ///
    /// <p>An array of objects that describe the metric data returned.</p>
    pub fn metric_data(mut self, input: crate::types::MetricDatapoint) -> Self {
        let mut v = self.metric_data.unwrap_or_default();
        v.push(input);
        self.metric_data = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that describe the metric data returned.</p>
    pub fn set_metric_data(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatapoint>>) -> Self {
        self.metric_data = input;
        self
    }
    /// <p>An array of objects that describe the metric data returned.</p>
    pub fn get_metric_data(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDatapoint>> {
        &self.metric_data
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRelationalDatabaseMetricDataOutput`](crate::operation::get_relational_database_metric_data::GetRelationalDatabaseMetricDataOutput).
    pub fn build(self) -> crate::operation::get_relational_database_metric_data::GetRelationalDatabaseMetricDataOutput {
        crate::operation::get_relational_database_metric_data::GetRelationalDatabaseMetricDataOutput {
            metric_name: self.metric_name,
            metric_data: self.metric_data,
            _request_id: self._request_id,
        }
    }
}
