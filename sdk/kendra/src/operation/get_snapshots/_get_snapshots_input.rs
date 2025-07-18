// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSnapshotsInput {
    /// <p>The identifier of the index to get search metrics data.</p>
    pub index_id: ::std::option::Option<::std::string::String>,
    /// <p>The time interval or time window to get search metrics data. The time interval uses the time zone of your index. You can view data in the following time windows:</p>
    /// <ul>
    /// <li>
    /// <p><code>THIS_WEEK</code>: The current week, starting on the Sunday and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_WEEK_AGO</code>: The previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>TWO_WEEKS_AGO</code>: The week before the previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>THIS_MONTH</code>: The current month, starting on the first day of the month and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_MONTH_AGO</code>: The previous month, starting on the first day of the month and ending on the last day of the month.</p></li>
    /// <li>
    /// <p><code>TWO_MONTHS_AGO</code>: The month before the previous month, starting on the first day of the month and ending on last day of the month.</p></li>
    /// </ul>
    pub interval: ::std::option::Option<crate::types::Interval>,
    /// <p>The metric you want to retrieve. You can specify only one metric per call.</p>
    /// <p>For more information about the metrics you can view, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/search-analytics.html">Gaining insights with search analytics</a>.</p>
    pub metric_type: ::std::option::Option<crate::types::MetricType>,
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of search metrics data.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of returned data for the metric.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetSnapshotsInput {
    /// <p>The identifier of the index to get search metrics data.</p>
    pub fn index_id(&self) -> ::std::option::Option<&str> {
        self.index_id.as_deref()
    }
    /// <p>The time interval or time window to get search metrics data. The time interval uses the time zone of your index. You can view data in the following time windows:</p>
    /// <ul>
    /// <li>
    /// <p><code>THIS_WEEK</code>: The current week, starting on the Sunday and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_WEEK_AGO</code>: The previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>TWO_WEEKS_AGO</code>: The week before the previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>THIS_MONTH</code>: The current month, starting on the first day of the month and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_MONTH_AGO</code>: The previous month, starting on the first day of the month and ending on the last day of the month.</p></li>
    /// <li>
    /// <p><code>TWO_MONTHS_AGO</code>: The month before the previous month, starting on the first day of the month and ending on last day of the month.</p></li>
    /// </ul>
    pub fn interval(&self) -> ::std::option::Option<&crate::types::Interval> {
        self.interval.as_ref()
    }
    /// <p>The metric you want to retrieve. You can specify only one metric per call.</p>
    /// <p>For more information about the metrics you can view, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/search-analytics.html">Gaining insights with search analytics</a>.</p>
    pub fn metric_type(&self) -> ::std::option::Option<&crate::types::MetricType> {
        self.metric_type.as_ref()
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of search metrics data.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of returned data for the metric.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetSnapshotsInput {
    /// Creates a new builder-style object to manufacture [`GetSnapshotsInput`](crate::operation::get_snapshots::GetSnapshotsInput).
    pub fn builder() -> crate::operation::get_snapshots::builders::GetSnapshotsInputBuilder {
        crate::operation::get_snapshots::builders::GetSnapshotsInputBuilder::default()
    }
}

/// A builder for [`GetSnapshotsInput`](crate::operation::get_snapshots::GetSnapshotsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSnapshotsInputBuilder {
    pub(crate) index_id: ::std::option::Option<::std::string::String>,
    pub(crate) interval: ::std::option::Option<crate::types::Interval>,
    pub(crate) metric_type: ::std::option::Option<crate::types::MetricType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetSnapshotsInputBuilder {
    /// <p>The identifier of the index to get search metrics data.</p>
    /// This field is required.
    pub fn index_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the index to get search metrics data.</p>
    pub fn set_index_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_id = input;
        self
    }
    /// <p>The identifier of the index to get search metrics data.</p>
    pub fn get_index_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_id
    }
    /// <p>The time interval or time window to get search metrics data. The time interval uses the time zone of your index. You can view data in the following time windows:</p>
    /// <ul>
    /// <li>
    /// <p><code>THIS_WEEK</code>: The current week, starting on the Sunday and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_WEEK_AGO</code>: The previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>TWO_WEEKS_AGO</code>: The week before the previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>THIS_MONTH</code>: The current month, starting on the first day of the month and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_MONTH_AGO</code>: The previous month, starting on the first day of the month and ending on the last day of the month.</p></li>
    /// <li>
    /// <p><code>TWO_MONTHS_AGO</code>: The month before the previous month, starting on the first day of the month and ending on last day of the month.</p></li>
    /// </ul>
    /// This field is required.
    pub fn interval(mut self, input: crate::types::Interval) -> Self {
        self.interval = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time interval or time window to get search metrics data. The time interval uses the time zone of your index. You can view data in the following time windows:</p>
    /// <ul>
    /// <li>
    /// <p><code>THIS_WEEK</code>: The current week, starting on the Sunday and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_WEEK_AGO</code>: The previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>TWO_WEEKS_AGO</code>: The week before the previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>THIS_MONTH</code>: The current month, starting on the first day of the month and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_MONTH_AGO</code>: The previous month, starting on the first day of the month and ending on the last day of the month.</p></li>
    /// <li>
    /// <p><code>TWO_MONTHS_AGO</code>: The month before the previous month, starting on the first day of the month and ending on last day of the month.</p></li>
    /// </ul>
    pub fn set_interval(mut self, input: ::std::option::Option<crate::types::Interval>) -> Self {
        self.interval = input;
        self
    }
    /// <p>The time interval or time window to get search metrics data. The time interval uses the time zone of your index. You can view data in the following time windows:</p>
    /// <ul>
    /// <li>
    /// <p><code>THIS_WEEK</code>: The current week, starting on the Sunday and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_WEEK_AGO</code>: The previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>TWO_WEEKS_AGO</code>: The week before the previous week, starting on the Sunday and ending on the following Saturday.</p></li>
    /// <li>
    /// <p><code>THIS_MONTH</code>: The current month, starting on the first day of the month and ending on the day before the current date.</p></li>
    /// <li>
    /// <p><code>ONE_MONTH_AGO</code>: The previous month, starting on the first day of the month and ending on the last day of the month.</p></li>
    /// <li>
    /// <p><code>TWO_MONTHS_AGO</code>: The month before the previous month, starting on the first day of the month and ending on last day of the month.</p></li>
    /// </ul>
    pub fn get_interval(&self) -> &::std::option::Option<crate::types::Interval> {
        &self.interval
    }
    /// <p>The metric you want to retrieve. You can specify only one metric per call.</p>
    /// <p>For more information about the metrics you can view, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/search-analytics.html">Gaining insights with search analytics</a>.</p>
    /// This field is required.
    pub fn metric_type(mut self, input: crate::types::MetricType) -> Self {
        self.metric_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metric you want to retrieve. You can specify only one metric per call.</p>
    /// <p>For more information about the metrics you can view, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/search-analytics.html">Gaining insights with search analytics</a>.</p>
    pub fn set_metric_type(mut self, input: ::std::option::Option<crate::types::MetricType>) -> Self {
        self.metric_type = input;
        self
    }
    /// <p>The metric you want to retrieve. You can specify only one metric per call.</p>
    /// <p>For more information about the metrics you can view, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/search-analytics.html">Gaining insights with search analytics</a>.</p>
    pub fn get_metric_type(&self) -> &::std::option::Option<crate::types::MetricType> {
        &self.metric_type
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of search metrics data.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of search metrics data.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of search metrics data.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of returned data for the metric.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of returned data for the metric.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of returned data for the metric.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetSnapshotsInput`](crate::operation::get_snapshots::GetSnapshotsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_snapshots::GetSnapshotsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_snapshots::GetSnapshotsInput {
            index_id: self.index_id,
            interval: self.interval,
            metric_type: self.metric_type,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
