// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSessionAnalyticsDataInput {
    /// <p>The identifier for the bot for which you want to retrieve session analytics.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that marks the beginning of the range of time for which you want to see session analytics.</p>
    pub start_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that marks the end of the range of time for which you want to see session analytics.</p>
    pub end_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>An object specifying the measure and method by which to sort the session analytics data.</p>
    pub sort_by: ::std::option::Option<crate::types::SessionDataSortBy>,
    /// <p>A list of objects, each of which describes a condition by which you want to filter the results.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::AnalyticsSessionFilter>>,
    /// <p>The maximum number of results to return in each page of results. If there are fewer results than the maximum page size, only the actual number of results are returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListSessionAnalyticsDataInput {
    /// <p>The identifier for the bot for which you want to retrieve session analytics.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The date and time that marks the beginning of the range of time for which you want to see session analytics.</p>
    pub fn start_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_date_time.as_ref()
    }
    /// <p>The date and time that marks the end of the range of time for which you want to see session analytics.</p>
    pub fn end_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date_time.as_ref()
    }
    /// <p>An object specifying the measure and method by which to sort the session analytics data.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::SessionDataSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>A list of objects, each of which describes a condition by which you want to filter the results.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::AnalyticsSessionFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return in each page of results. If there are fewer results than the maximum page size, only the actual number of results are returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListSessionAnalyticsDataInput {
    /// Creates a new builder-style object to manufacture [`ListSessionAnalyticsDataInput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataInput).
    pub fn builder() -> crate::operation::list_session_analytics_data::builders::ListSessionAnalyticsDataInputBuilder {
        crate::operation::list_session_analytics_data::builders::ListSessionAnalyticsDataInputBuilder::default()
    }
}

/// A builder for [`ListSessionAnalyticsDataInput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSessionAnalyticsDataInputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) start_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sort_by: ::std::option::Option<crate::types::SessionDataSortBy>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::AnalyticsSessionFilter>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListSessionAnalyticsDataInputBuilder {
    /// <p>The identifier for the bot for which you want to retrieve session analytics.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the bot for which you want to retrieve session analytics.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier for the bot for which you want to retrieve session analytics.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The date and time that marks the beginning of the range of time for which you want to see session analytics.</p>
    /// This field is required.
    pub fn start_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that marks the beginning of the range of time for which you want to see session analytics.</p>
    pub fn set_start_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date_time = input;
        self
    }
    /// <p>The date and time that marks the beginning of the range of time for which you want to see session analytics.</p>
    pub fn get_start_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date_time
    }
    /// <p>The date and time that marks the end of the range of time for which you want to see session analytics.</p>
    /// This field is required.
    pub fn end_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that marks the end of the range of time for which you want to see session analytics.</p>
    pub fn set_end_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date_time = input;
        self
    }
    /// <p>The date and time that marks the end of the range of time for which you want to see session analytics.</p>
    pub fn get_end_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date_time
    }
    /// <p>An object specifying the measure and method by which to sort the session analytics data.</p>
    pub fn sort_by(mut self, input: crate::types::SessionDataSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object specifying the measure and method by which to sort the session analytics data.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::SessionDataSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>An object specifying the measure and method by which to sort the session analytics data.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::SessionDataSortBy> {
        &self.sort_by
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>A list of objects, each of which describes a condition by which you want to filter the results.</p>
    pub fn filters(mut self, input: crate::types::AnalyticsSessionFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects, each of which describes a condition by which you want to filter the results.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AnalyticsSessionFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A list of objects, each of which describes a condition by which you want to filter the results.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AnalyticsSessionFilter>> {
        &self.filters
    }
    /// <p>The maximum number of results to return in each page of results. If there are fewer results than the maximum page size, only the actual number of results are returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in each page of results. If there are fewer results than the maximum page size, only the actual number of results are returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in each page of results. If there are fewer results than the maximum page size, only the actual number of results are returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response from the ListSessionAnalyticsData operation contains more results than specified in the maxResults parameter, a token is returned in the response.</p>
    /// <p>Use the returned token in the nextToken parameter of a ListSessionAnalyticsData request to return the next page of results. For a complete set of results, call the ListSessionAnalyticsData operation until the nextToken returned in the response is null.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListSessionAnalyticsDataInput`](crate::operation::list_session_analytics_data::ListSessionAnalyticsDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_session_analytics_data::ListSessionAnalyticsDataInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_session_analytics_data::ListSessionAnalyticsDataInput {
            bot_id: self.bot_id,
            start_date_time: self.start_date_time,
            end_date_time: self.end_date_time,
            sort_by: self.sort_by,
            filters: self.filters,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
