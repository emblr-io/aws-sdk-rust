// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListJobExecutionsForThingOutput {
    /// <p>A list of job execution summaries.</p>
    pub execution_summaries: ::std::option::Option<::std::vec::Vec<crate::types::JobExecutionSummaryForThing>>,
    /// <p>The token for the next set of results, or <b>null</b> if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobExecutionsForThingOutput {
    /// <p>A list of job execution summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.execution_summaries.is_none()`.
    pub fn execution_summaries(&self) -> &[crate::types::JobExecutionSummaryForThing] {
        self.execution_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListJobExecutionsForThingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListJobExecutionsForThingOutput {
    /// Creates a new builder-style object to manufacture [`ListJobExecutionsForThingOutput`](crate::operation::list_job_executions_for_thing::ListJobExecutionsForThingOutput).
    pub fn builder() -> crate::operation::list_job_executions_for_thing::builders::ListJobExecutionsForThingOutputBuilder {
        crate::operation::list_job_executions_for_thing::builders::ListJobExecutionsForThingOutputBuilder::default()
    }
}

/// A builder for [`ListJobExecutionsForThingOutput`](crate::operation::list_job_executions_for_thing::ListJobExecutionsForThingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListJobExecutionsForThingOutputBuilder {
    pub(crate) execution_summaries: ::std::option::Option<::std::vec::Vec<crate::types::JobExecutionSummaryForThing>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobExecutionsForThingOutputBuilder {
    /// Appends an item to `execution_summaries`.
    ///
    /// To override the contents of this collection use [`set_execution_summaries`](Self::set_execution_summaries).
    ///
    /// <p>A list of job execution summaries.</p>
    pub fn execution_summaries(mut self, input: crate::types::JobExecutionSummaryForThing) -> Self {
        let mut v = self.execution_summaries.unwrap_or_default();
        v.push(input);
        self.execution_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of job execution summaries.</p>
    pub fn set_execution_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::JobExecutionSummaryForThing>>) -> Self {
        self.execution_summaries = input;
        self
    }
    /// <p>A list of job execution summaries.</p>
    pub fn get_execution_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::JobExecutionSummaryForThing>> {
        &self.execution_summaries
    }
    /// <p>The token for the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or <b>null</b> if there are no additional results.</p>
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
    /// Consumes the builder and constructs a [`ListJobExecutionsForThingOutput`](crate::operation::list_job_executions_for_thing::ListJobExecutionsForThingOutput).
    pub fn build(self) -> crate::operation::list_job_executions_for_thing::ListJobExecutionsForThingOutput {
        crate::operation::list_job_executions_for_thing::ListJobExecutionsForThingOutput {
            execution_summaries: self.execution_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
