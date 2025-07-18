// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCopyJobSummariesOutput {
    /// <p>This return shows a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub copy_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::CopyJobSummary>>,
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
impl ListCopyJobSummariesOutput {
    /// <p>This return shows a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.copy_job_summaries.is_none()`.
    pub fn copy_job_summaries(&self) -> &[crate::types::CopyJobSummary] {
        self.copy_job_summaries.as_deref().unwrap_or_default()
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
impl ::aws_types::request_id::RequestId for ListCopyJobSummariesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCopyJobSummariesOutput {
    /// Creates a new builder-style object to manufacture [`ListCopyJobSummariesOutput`](crate::operation::list_copy_job_summaries::ListCopyJobSummariesOutput).
    pub fn builder() -> crate::operation::list_copy_job_summaries::builders::ListCopyJobSummariesOutputBuilder {
        crate::operation::list_copy_job_summaries::builders::ListCopyJobSummariesOutputBuilder::default()
    }
}

/// A builder for [`ListCopyJobSummariesOutput`](crate::operation::list_copy_job_summaries::ListCopyJobSummariesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCopyJobSummariesOutputBuilder {
    pub(crate) copy_job_summaries: ::std::option::Option<::std::vec::Vec<crate::types::CopyJobSummary>>,
    pub(crate) aggregation_period: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListCopyJobSummariesOutputBuilder {
    /// Appends an item to `copy_job_summaries`.
    ///
    /// To override the contents of this collection use [`set_copy_job_summaries`](Self::set_copy_job_summaries).
    ///
    /// <p>This return shows a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn copy_job_summaries(mut self, input: crate::types::CopyJobSummary) -> Self {
        let mut v = self.copy_job_summaries.unwrap_or_default();
        v.push(input);
        self.copy_job_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>This return shows a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn set_copy_job_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CopyJobSummary>>) -> Self {
        self.copy_job_summaries = input;
        self
    }
    /// <p>This return shows a summary that contains Region, Account, State, ResourceType, MessageCategory, StartTime, EndTime, and Count of included jobs.</p>
    pub fn get_copy_job_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CopyJobSummary>> {
        &self.copy_job_summaries
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
    /// Consumes the builder and constructs a [`ListCopyJobSummariesOutput`](crate::operation::list_copy_job_summaries::ListCopyJobSummariesOutput).
    pub fn build(self) -> crate::operation::list_copy_job_summaries::ListCopyJobSummariesOutput {
        crate::operation::list_copy_job_summaries::ListCopyJobSummariesOutput {
            copy_job_summaries: self.copy_job_summaries,
            aggregation_period: self.aggregation_period,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
