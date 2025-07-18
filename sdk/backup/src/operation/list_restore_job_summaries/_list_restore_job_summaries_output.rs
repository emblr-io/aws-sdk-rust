// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRestoreJobSummariesOutput {
    /// <p>This return contains a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub restore_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::RestoreJobSummary>>,
    /// <p>The period for the returned results.</p>
    /// <ul>
    /// <li>
    /// <p><code>ONE_DAY</code> - The daily job count for the prior 14 days.</p></li>
    /// <li>
    /// <p><code>SEVEN_DAYS</code> - The aggregated job count for the prior 7 days.</p></li>
    /// <li>
    /// <p><code>FOURTEEN_DAYS</code> - The aggregated job count for prior 14 days.</p></li>
    /// </ul>
    pub aggregation_period: ::std::option::Option<::std::string::String>,
    /// <p>The next item following a partial list of returned resources. For example, if a request is made to return <code>MaxResults</code> number of resources, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRestoreJobSummariesOutput {
    /// <p>This return contains a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.restore_job_summaries.is_none()`.
    pub fn restore_job_summaries(&self) -> &[crate::types::RestoreJobSummary] {
        self.restore_job_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The period for the returned results.</p>
    /// <ul>
    /// <li>
    /// <p><code>ONE_DAY</code> - The daily job count for the prior 14 days.</p></li>
    /// <li>
    /// <p><code>SEVEN_DAYS</code> - The aggregated job count for the prior 7 days.</p></li>
    /// <li>
    /// <p><code>FOURTEEN_DAYS</code> - The aggregated job count for prior 14 days.</p></li>
    /// </ul>
    pub fn aggregation_period(&self) -> ::std::option::Option<&str> {
        self.aggregation_period.as_deref()
    }
    /// <p>The next item following a partial list of returned resources. For example, if a request is made to return <code>MaxResults</code> number of resources, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRestoreJobSummariesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRestoreJobSummariesOutput {
    /// Creates a new builder-style object to manufacture [`ListRestoreJobSummariesOutput`](crate::operation::list_restore_job_summaries::ListRestoreJobSummariesOutput).
    pub fn builder() -> crate::operation::list_restore_job_summaries::builders::ListRestoreJobSummariesOutputBuilder {
        crate::operation::list_restore_job_summaries::builders::ListRestoreJobSummariesOutputBuilder::default()
    }
}

/// A builder for [`ListRestoreJobSummariesOutput`](crate::operation::list_restore_job_summaries::ListRestoreJobSummariesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRestoreJobSummariesOutputBuilder {
    pub(crate) restore_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::RestoreJobSummary>>,
    pub(crate) aggregation_period: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRestoreJobSummariesOutputBuilder {
    /// Appends an item to `restore_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_restore_job_summaries`](Self::set_restore_job_summaries).
    ///
    /// <p>This return contains a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn restore_job_summaries(mut self, input: crate::types::RestoreJobSummary) -> Self {
        let mut v = self.restore_job_summaries.unwrap_or_default();
        v.push(input);
        self.restore_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>This return contains a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn set_restore_job_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RestoreJobSummary>>) -> Self {
        self.restore_job_summaries = input;
        self
    }
    /// <p>This return contains a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn get_restore_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RestoreJobSummary>> {
        &self.restore_job_summaries
    }
    /// <p>The period for the returned results.</p>
    /// <ul>
    /// <li>
    /// <p><code>ONE_DAY</code> - The daily job count for the prior 14 days.</p></li>
    /// <li>
    /// <p><code>SEVEN_DAYS</code> - The aggregated job count for the prior 7 days.</p></li>
    /// <li>
    /// <p><code>FOURTEEN_DAYS</code> - The aggregated job count for prior 14 days.</p></li>
    /// </ul>
    pub fn aggregation_period(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aggregation_period = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The period for the returned results.</p>
    /// <ul>
    /// <li>
    /// <p><code>ONE_DAY</code> - The daily job count for the prior 14 days.</p></li>
    /// <li>
    /// <p><code>SEVEN_DAYS</code> - The aggregated job count for the prior 7 days.</p></li>
    /// <li>
    /// <p><code>FOURTEEN_DAYS</code> - The aggregated job count for prior 14 days.</p></li>
    /// </ul>
    pub fn set_aggregation_period(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aggregation_period = input;
        self
    }
    /// <p>The period for the returned results.</p>
    /// <ul>
    /// <li>
    /// <p><code>ONE_DAY</code> - The daily job count for the prior 14 days.</p></li>
    /// <li>
    /// <p><code>SEVEN_DAYS</code> - The aggregated job count for the prior 7 days.</p></li>
    /// <li>
    /// <p><code>FOURTEEN_DAYS</code> - The aggregated job count for prior 14 days.</p></li>
    /// </ul>
    pub fn get_aggregation_period(&self) -> &::std::option::Option<::std::string::String> {
        &self.aggregation_period
    }
    /// <p>The next item following a partial list of returned resources. For example, if a request is made to return <code>MaxResults</code> number of resources, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next item following a partial list of returned resources. For example, if a request is made to return <code>MaxResults</code> number of resources, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next item following a partial list of returned resources. For example, if a request is made to return <code>MaxResults</code> number of resources, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
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
    /// Consumes the builder and constructs a [`ListRestoreJobSummariesOutput`](crate::operation::list_restore_job_summaries::ListRestoreJobSummariesOutput).
    pub fn build(self) -> crate::operation::list_restore_job_summaries::ListRestoreJobSummariesOutput {
        crate::operation::list_restore_job_summaries::ListRestoreJobSummariesOutput {
            restore_job_summaries: self.restore_job_summaries,
            aggregation_period: self.aggregation_period,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
