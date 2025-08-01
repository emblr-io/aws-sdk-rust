// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAvailableResourceMetricsInput {
    /// <p>The Amazon Web Services service for which Performance Insights returns metrics.</p>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
    /// <p>An immutable identifier for a data source that is unique within an Amazon Web Services Region. Performance Insights gathers metrics from this data source. To use an Amazon RDS DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VWZ</code>.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The types of metrics to return in the response. Valid values in the array include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>os</code> (OS counter metrics) - All engines</p></li>
    /// <li>
    /// <p><code>db</code> (DB load metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql.stats</code> (per-SQL metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql_tokenized.stats</code> (per-SQL digest metrics) - All engines except for Amazon DocumentDB</p></li>
    /// </ul>
    pub metric_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxRecords</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return. If the <code>MaxRecords</code> value is less than the number of existing items, the response includes a pagination token.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListAvailableResourceMetricsInput {
    /// <p>The Amazon Web Services service for which Performance Insights returns metrics.</p>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
    /// <p>An immutable identifier for a data source that is unique within an Amazon Web Services Region. Performance Insights gathers metrics from this data source. To use an Amazon RDS DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VWZ</code>.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The types of metrics to return in the response. Valid values in the array include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>os</code> (OS counter metrics) - All engines</p></li>
    /// <li>
    /// <p><code>db</code> (DB load metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql.stats</code> (per-SQL metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql_tokenized.stats</code> (per-SQL digest metrics) - All engines except for Amazon DocumentDB</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.metric_types.is_none()`.
    pub fn metric_types(&self) -> &[::std::string::String] {
        self.metric_types.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return. If the <code>MaxRecords</code> value is less than the number of existing items, the response includes a pagination token.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListAvailableResourceMetricsInput {
    /// Creates a new builder-style object to manufacture [`ListAvailableResourceMetricsInput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsInput).
    pub fn builder() -> crate::operation::list_available_resource_metrics::builders::ListAvailableResourceMetricsInputBuilder {
        crate::operation::list_available_resource_metrics::builders::ListAvailableResourceMetricsInputBuilder::default()
    }
}

/// A builder for [`ListAvailableResourceMetricsInput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAvailableResourceMetricsInputBuilder {
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) metric_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListAvailableResourceMetricsInputBuilder {
    /// <p>The Amazon Web Services service for which Performance Insights returns metrics.</p>
    /// This field is required.
    pub fn service_type(mut self, input: crate::types::ServiceType) -> Self {
        self.service_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Web Services service for which Performance Insights returns metrics.</p>
    pub fn set_service_type(mut self, input: ::std::option::Option<crate::types::ServiceType>) -> Self {
        self.service_type = input;
        self
    }
    /// <p>The Amazon Web Services service for which Performance Insights returns metrics.</p>
    pub fn get_service_type(&self) -> &::std::option::Option<crate::types::ServiceType> {
        &self.service_type
    }
    /// <p>An immutable identifier for a data source that is unique within an Amazon Web Services Region. Performance Insights gathers metrics from this data source. To use an Amazon RDS DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VWZ</code>.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An immutable identifier for a data source that is unique within an Amazon Web Services Region. Performance Insights gathers metrics from this data source. To use an Amazon RDS DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VWZ</code>.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>An immutable identifier for a data source that is unique within an Amazon Web Services Region. Performance Insights gathers metrics from this data source. To use an Amazon RDS DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VWZ</code>.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Appends an item to `metric_types`.
    ///
    /// To override the contents of this collection use [`set_metric_types`](Self::set_metric_types).
    ///
    /// <p>The types of metrics to return in the response. Valid values in the array include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>os</code> (OS counter metrics) - All engines</p></li>
    /// <li>
    /// <p><code>db</code> (DB load metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql.stats</code> (per-SQL metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql_tokenized.stats</code> (per-SQL digest metrics) - All engines except for Amazon DocumentDB</p></li>
    /// </ul>
    pub fn metric_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.metric_types.unwrap_or_default();
        v.push(input.into());
        self.metric_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of metrics to return in the response. Valid values in the array include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>os</code> (OS counter metrics) - All engines</p></li>
    /// <li>
    /// <p><code>db</code> (DB load metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql.stats</code> (per-SQL metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql_tokenized.stats</code> (per-SQL digest metrics) - All engines except for Amazon DocumentDB</p></li>
    /// </ul>
    pub fn set_metric_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.metric_types = input;
        self
    }
    /// <p>The types of metrics to return in the response. Valid values in the array include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>os</code> (OS counter metrics) - All engines</p></li>
    /// <li>
    /// <p><code>db</code> (DB load metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql.stats</code> (per-SQL metrics) - All engines except for Amazon DocumentDB</p></li>
    /// <li>
    /// <p><code>db.sql_tokenized.stats</code> (per-SQL digest metrics) - All engines except for Amazon DocumentDB</p></li>
    /// </ul>
    pub fn get_metric_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.metric_types
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return. If the <code>MaxRecords</code> value is less than the number of existing items, the response includes a pagination token.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return. If the <code>MaxRecords</code> value is less than the number of existing items, the response includes a pagination token.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return. If the <code>MaxRecords</code> value is less than the number of existing items, the response includes a pagination token.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListAvailableResourceMetricsInput`](crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_available_resource_metrics::ListAvailableResourceMetricsInput {
            service_type: self.service_type,
            identifier: self.identifier,
            metric_types: self.metric_types,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
