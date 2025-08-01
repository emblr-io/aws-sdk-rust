// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListForecastsInput {
    /// <p>If the result of the previous request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of results, use the token in the next request. Tokens expire after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of items to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>An array of filters. For each filter, you provide a condition and a match statement. The condition is either <code>IS</code> or <code>IS_NOT</code>, which specifies whether to include or exclude the forecasts that match the statement from the list, respectively. The match statement consists of a key and a value.</p>
    /// <p><b>Filter properties</b></p>
    /// <ul>
    /// <li>
    /// <p><code>Condition</code> - The condition to apply. Valid values are <code>IS</code> and <code>IS_NOT</code>. To include the forecasts that match the statement, specify <code>IS</code>. To exclude matching forecasts, specify <code>IS_NOT</code>.</p></li>
    /// <li>
    /// <p><code>Key</code> - The name of the parameter to filter on. Valid values are <code>DatasetGroupArn</code>, <code>PredictorArn</code>, and <code>Status</code>.</p></li>
    /// <li>
    /// <p><code>Value</code> - The value to match.</p></li>
    /// </ul>
    /// <p>For example, to list all forecasts whose status is not ACTIVE, you would specify:</p>
    /// <p><code>"Filters": \[ { "Condition": "IS_NOT", "Key": "Status", "Value": "ACTIVE" } \]</code></p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl ListForecastsInput {
    /// <p>If the result of the previous request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of results, use the token in the next request. Tokens expire after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The number of items to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>An array of filters. For each filter, you provide a condition and a match statement. The condition is either <code>IS</code> or <code>IS_NOT</code>, which specifies whether to include or exclude the forecasts that match the statement from the list, respectively. The match statement consists of a key and a value.</p>
    /// <p><b>Filter properties</b></p>
    /// <ul>
    /// <li>
    /// <p><code>Condition</code> - The condition to apply. Valid values are <code>IS</code> and <code>IS_NOT</code>. To include the forecasts that match the statement, specify <code>IS</code>. To exclude matching forecasts, specify <code>IS_NOT</code>.</p></li>
    /// <li>
    /// <p><code>Key</code> - The name of the parameter to filter on. Valid values are <code>DatasetGroupArn</code>, <code>PredictorArn</code>, and <code>Status</code>.</p></li>
    /// <li>
    /// <p><code>Value</code> - The value to match.</p></li>
    /// </ul>
    /// <p>For example, to list all forecasts whose status is not ACTIVE, you would specify:</p>
    /// <p><code>"Filters": \[ { "Condition": "IS_NOT", "Key": "Status", "Value": "ACTIVE" } \]</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl ListForecastsInput {
    /// Creates a new builder-style object to manufacture [`ListForecastsInput`](crate::operation::list_forecasts::ListForecastsInput).
    pub fn builder() -> crate::operation::list_forecasts::builders::ListForecastsInputBuilder {
        crate::operation::list_forecasts::builders::ListForecastsInputBuilder::default()
    }
}

/// A builder for [`ListForecastsInput`](crate::operation::list_forecasts::ListForecastsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListForecastsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl ListForecastsInputBuilder {
    /// <p>If the result of the previous request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of results, use the token in the next request. Tokens expire after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of the previous request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of results, use the token in the next request. Tokens expire after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the result of the previous request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of results, use the token in the next request. Tokens expire after 24 hours.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The number of items to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of items to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of items to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An array of filters. For each filter, you provide a condition and a match statement. The condition is either <code>IS</code> or <code>IS_NOT</code>, which specifies whether to include or exclude the forecasts that match the statement from the list, respectively. The match statement consists of a key and a value.</p>
    /// <p><b>Filter properties</b></p>
    /// <ul>
    /// <li>
    /// <p><code>Condition</code> - The condition to apply. Valid values are <code>IS</code> and <code>IS_NOT</code>. To include the forecasts that match the statement, specify <code>IS</code>. To exclude matching forecasts, specify <code>IS_NOT</code>.</p></li>
    /// <li>
    /// <p><code>Key</code> - The name of the parameter to filter on. Valid values are <code>DatasetGroupArn</code>, <code>PredictorArn</code>, and <code>Status</code>.</p></li>
    /// <li>
    /// <p><code>Value</code> - The value to match.</p></li>
    /// </ul>
    /// <p>For example, to list all forecasts whose status is not ACTIVE, you would specify:</p>
    /// <p><code>"Filters": \[ { "Condition": "IS_NOT", "Key": "Status", "Value": "ACTIVE" } \]</code></p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of filters. For each filter, you provide a condition and a match statement. The condition is either <code>IS</code> or <code>IS_NOT</code>, which specifies whether to include or exclude the forecasts that match the statement from the list, respectively. The match statement consists of a key and a value.</p>
    /// <p><b>Filter properties</b></p>
    /// <ul>
    /// <li>
    /// <p><code>Condition</code> - The condition to apply. Valid values are <code>IS</code> and <code>IS_NOT</code>. To include the forecasts that match the statement, specify <code>IS</code>. To exclude matching forecasts, specify <code>IS_NOT</code>.</p></li>
    /// <li>
    /// <p><code>Key</code> - The name of the parameter to filter on. Valid values are <code>DatasetGroupArn</code>, <code>PredictorArn</code>, and <code>Status</code>.</p></li>
    /// <li>
    /// <p><code>Value</code> - The value to match.</p></li>
    /// </ul>
    /// <p>For example, to list all forecasts whose status is not ACTIVE, you would specify:</p>
    /// <p><code>"Filters": \[ { "Condition": "IS_NOT", "Key": "Status", "Value": "ACTIVE" } \]</code></p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An array of filters. For each filter, you provide a condition and a match statement. The condition is either <code>IS</code> or <code>IS_NOT</code>, which specifies whether to include or exclude the forecasts that match the statement from the list, respectively. The match statement consists of a key and a value.</p>
    /// <p><b>Filter properties</b></p>
    /// <ul>
    /// <li>
    /// <p><code>Condition</code> - The condition to apply. Valid values are <code>IS</code> and <code>IS_NOT</code>. To include the forecasts that match the statement, specify <code>IS</code>. To exclude matching forecasts, specify <code>IS_NOT</code>.</p></li>
    /// <li>
    /// <p><code>Key</code> - The name of the parameter to filter on. Valid values are <code>DatasetGroupArn</code>, <code>PredictorArn</code>, and <code>Status</code>.</p></li>
    /// <li>
    /// <p><code>Value</code> - The value to match.</p></li>
    /// </ul>
    /// <p>For example, to list all forecasts whose status is not ACTIVE, you would specify:</p>
    /// <p><code>"Filters": \[ { "Condition": "IS_NOT", "Key": "Status", "Value": "ACTIVE" } \]</code></p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`ListForecastsInput`](crate::operation::list_forecasts::ListForecastsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_forecasts::ListForecastsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_forecasts::ListForecastsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            filters: self.filters,
        })
    }
}
