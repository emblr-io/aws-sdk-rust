// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMetricsInput {
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of results to include in the response. If more results exist than the specified <code>MaxResults</code> value, a token is included in the response so that the remaining results can be retrieved.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Indicates the list of fields in the data source.</p>
    pub fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
    /// <p>Indicates the data source of the metrics.</p>
    pub data_source: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the list of all the conditions that were applied on the metrics.</p>
    pub conditions: ::std::option::Option<::std::vec::Vec<crate::types::Condition>>,
    /// <p>(Optional) Indicates the order in which you want to sort the fields in the metrics. By default, the fields are sorted in the ascending order.</p>
    pub sorts: ::std::option::Option<::std::vec::Vec<crate::types::Sort>>,
}
impl ListMetricsInput {
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of results to include in the response. If more results exist than the specified <code>MaxResults</code> value, a token is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Indicates the list of fields in the data source.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fields.is_none()`.
    pub fn fields(&self) -> &[crate::types::Field] {
        self.fields.as_deref().unwrap_or_default()
    }
    /// <p>Indicates the data source of the metrics.</p>
    pub fn data_source(&self) -> ::std::option::Option<&str> {
        self.data_source.as_deref()
    }
    /// <p>Indicates the list of all the conditions that were applied on the metrics.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.conditions.is_none()`.
    pub fn conditions(&self) -> &[crate::types::Condition] {
        self.conditions.as_deref().unwrap_or_default()
    }
    /// <p>(Optional) Indicates the order in which you want to sort the fields in the metrics. By default, the fields are sorted in the ascending order.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sorts.is_none()`.
    pub fn sorts(&self) -> &[crate::types::Sort] {
        self.sorts.as_deref().unwrap_or_default()
    }
}
impl ListMetricsInput {
    /// Creates a new builder-style object to manufacture [`ListMetricsInput`](crate::operation::list_metrics::ListMetricsInput).
    pub fn builder() -> crate::operation::list_metrics::builders::ListMetricsInputBuilder {
        crate::operation::list_metrics::builders::ListMetricsInputBuilder::default()
    }
}

/// A builder for [`ListMetricsInput`](crate::operation::list_metrics::ListMetricsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMetricsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
    pub(crate) data_source: ::std::option::Option<::std::string::String>,
    pub(crate) conditions: ::std::option::Option<::std::vec::Vec<crate::types::Condition>>,
    pub(crate) sorts: ::std::option::Option<::std::vec::Vec<crate::types::Sort>>,
}
impl ListMetricsInputBuilder {
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of results to include in the response. If more results exist than the specified <code>MaxResults</code> value, a token is included in the response so that the remaining results can be retrieved.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of results to include in the response. If more results exist than the specified <code>MaxResults</code> value, a token is included in the response so that the remaining results can be retrieved.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of results to include in the response. If more results exist than the specified <code>MaxResults</code> value, a token is included in the response so that the remaining results can be retrieved.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `fields`.
    ///
    /// To override the contents of this collection use [`set_fields`](Self::set_fields).
    ///
    /// <p>Indicates the list of fields in the data source.</p>
    pub fn fields(mut self, input: crate::types::Field) -> Self {
        let mut v = self.fields.unwrap_or_default();
        v.push(input);
        self.fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the list of fields in the data source.</p>
    pub fn set_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Field>>) -> Self {
        self.fields = input;
        self
    }
    /// <p>Indicates the list of fields in the data source.</p>
    pub fn get_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Field>> {
        &self.fields
    }
    /// <p>Indicates the data source of the metrics.</p>
    pub fn data_source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the data source of the metrics.</p>
    pub fn set_data_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source = input;
        self
    }
    /// <p>Indicates the data source of the metrics.</p>
    pub fn get_data_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source
    }
    /// Appends an item to `conditions`.
    ///
    /// To override the contents of this collection use [`set_conditions`](Self::set_conditions).
    ///
    /// <p>Indicates the list of all the conditions that were applied on the metrics.</p>
    pub fn conditions(mut self, input: crate::types::Condition) -> Self {
        let mut v = self.conditions.unwrap_or_default();
        v.push(input);
        self.conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the list of all the conditions that were applied on the metrics.</p>
    pub fn set_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Condition>>) -> Self {
        self.conditions = input;
        self
    }
    /// <p>Indicates the list of all the conditions that were applied on the metrics.</p>
    pub fn get_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Condition>> {
        &self.conditions
    }
    /// Appends an item to `sorts`.
    ///
    /// To override the contents of this collection use [`set_sorts`](Self::set_sorts).
    ///
    /// <p>(Optional) Indicates the order in which you want to sort the fields in the metrics. By default, the fields are sorted in the ascending order.</p>
    pub fn sorts(mut self, input: crate::types::Sort) -> Self {
        let mut v = self.sorts.unwrap_or_default();
        v.push(input);
        self.sorts = ::std::option::Option::Some(v);
        self
    }
    /// <p>(Optional) Indicates the order in which you want to sort the fields in the metrics. By default, the fields are sorted in the ascending order.</p>
    pub fn set_sorts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Sort>>) -> Self {
        self.sorts = input;
        self
    }
    /// <p>(Optional) Indicates the order in which you want to sort the fields in the metrics. By default, the fields are sorted in the ascending order.</p>
    pub fn get_sorts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Sort>> {
        &self.sorts
    }
    /// Consumes the builder and constructs a [`ListMetricsInput`](crate::operation::list_metrics::ListMetricsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_metrics::ListMetricsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_metrics::ListMetricsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            fields: self.fields,
            data_source: self.data_source,
            conditions: self.conditions,
            sorts: self.sorts,
        })
    }
}
