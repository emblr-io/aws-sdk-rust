// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The completion date, current state, submission time, and state change reason (if applicable) for the query execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryExecutionStatus {
    /// <p>The state of query execution. <code>QUEUED</code> indicates that the query has been submitted to the service, and Athena will execute the query as soon as resources are available. <code>RUNNING</code> indicates that the query is in execution phase. <code>SUCCEEDED</code> indicates that the query completed without errors. <code>FAILED</code> indicates that the query experienced an error and did not complete processing. <code>CANCELLED</code> indicates that a user input interrupted query execution.</p><note>
    /// <p>Athena automatically retries your queries in cases of certain transient errors. As a result, you may see the query state transition from <code>RUNNING</code> or <code>FAILED</code> to <code>QUEUED</code>.</p>
    /// </note>
    pub state: ::std::option::Option<crate::types::QueryExecutionState>,
    /// <p>Further detail about the status of the query.</p>
    pub state_change_reason: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the query was submitted.</p>
    pub submission_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the query completed.</p>
    pub completion_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Provides information about an Athena query error.</p>
    pub athena_error: ::std::option::Option<crate::types::AthenaError>,
}
impl QueryExecutionStatus {
    /// <p>The state of query execution. <code>QUEUED</code> indicates that the query has been submitted to the service, and Athena will execute the query as soon as resources are available. <code>RUNNING</code> indicates that the query is in execution phase. <code>SUCCEEDED</code> indicates that the query completed without errors. <code>FAILED</code> indicates that the query experienced an error and did not complete processing. <code>CANCELLED</code> indicates that a user input interrupted query execution.</p><note>
    /// <p>Athena automatically retries your queries in cases of certain transient errors. As a result, you may see the query state transition from <code>RUNNING</code> or <code>FAILED</code> to <code>QUEUED</code>.</p>
    /// </note>
    pub fn state(&self) -> ::std::option::Option<&crate::types::QueryExecutionState> {
        self.state.as_ref()
    }
    /// <p>Further detail about the status of the query.</p>
    pub fn state_change_reason(&self) -> ::std::option::Option<&str> {
        self.state_change_reason.as_deref()
    }
    /// <p>The date and time that the query was submitted.</p>
    pub fn submission_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.submission_date_time.as_ref()
    }
    /// <p>The date and time that the query completed.</p>
    pub fn completion_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_date_time.as_ref()
    }
    /// <p>Provides information about an Athena query error.</p>
    pub fn athena_error(&self) -> ::std::option::Option<&crate::types::AthenaError> {
        self.athena_error.as_ref()
    }
}
impl QueryExecutionStatus {
    /// Creates a new builder-style object to manufacture [`QueryExecutionStatus`](crate::types::QueryExecutionStatus).
    pub fn builder() -> crate::types::builders::QueryExecutionStatusBuilder {
        crate::types::builders::QueryExecutionStatusBuilder::default()
    }
}

/// A builder for [`QueryExecutionStatus`](crate::types::QueryExecutionStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryExecutionStatusBuilder {
    pub(crate) state: ::std::option::Option<crate::types::QueryExecutionState>,
    pub(crate) state_change_reason: ::std::option::Option<::std::string::String>,
    pub(crate) submission_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completion_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) athena_error: ::std::option::Option<crate::types::AthenaError>,
}
impl QueryExecutionStatusBuilder {
    /// <p>The state of query execution. <code>QUEUED</code> indicates that the query has been submitted to the service, and Athena will execute the query as soon as resources are available. <code>RUNNING</code> indicates that the query is in execution phase. <code>SUCCEEDED</code> indicates that the query completed without errors. <code>FAILED</code> indicates that the query experienced an error and did not complete processing. <code>CANCELLED</code> indicates that a user input interrupted query execution.</p><note>
    /// <p>Athena automatically retries your queries in cases of certain transient errors. As a result, you may see the query state transition from <code>RUNNING</code> or <code>FAILED</code> to <code>QUEUED</code>.</p>
    /// </note>
    pub fn state(mut self, input: crate::types::QueryExecutionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of query execution. <code>QUEUED</code> indicates that the query has been submitted to the service, and Athena will execute the query as soon as resources are available. <code>RUNNING</code> indicates that the query is in execution phase. <code>SUCCEEDED</code> indicates that the query completed without errors. <code>FAILED</code> indicates that the query experienced an error and did not complete processing. <code>CANCELLED</code> indicates that a user input interrupted query execution.</p><note>
    /// <p>Athena automatically retries your queries in cases of certain transient errors. As a result, you may see the query state transition from <code>RUNNING</code> or <code>FAILED</code> to <code>QUEUED</code>.</p>
    /// </note>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::QueryExecutionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of query execution. <code>QUEUED</code> indicates that the query has been submitted to the service, and Athena will execute the query as soon as resources are available. <code>RUNNING</code> indicates that the query is in execution phase. <code>SUCCEEDED</code> indicates that the query completed without errors. <code>FAILED</code> indicates that the query experienced an error and did not complete processing. <code>CANCELLED</code> indicates that a user input interrupted query execution.</p><note>
    /// <p>Athena automatically retries your queries in cases of certain transient errors. As a result, you may see the query state transition from <code>RUNNING</code> or <code>FAILED</code> to <code>QUEUED</code>.</p>
    /// </note>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::QueryExecutionState> {
        &self.state
    }
    /// <p>Further detail about the status of the query.</p>
    pub fn state_change_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_change_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Further detail about the status of the query.</p>
    pub fn set_state_change_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_change_reason = input;
        self
    }
    /// <p>Further detail about the status of the query.</p>
    pub fn get_state_change_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_change_reason
    }
    /// <p>The date and time that the query was submitted.</p>
    pub fn submission_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.submission_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the query was submitted.</p>
    pub fn set_submission_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.submission_date_time = input;
        self
    }
    /// <p>The date and time that the query was submitted.</p>
    pub fn get_submission_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.submission_date_time
    }
    /// <p>The date and time that the query completed.</p>
    pub fn completion_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the query completed.</p>
    pub fn set_completion_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_date_time = input;
        self
    }
    /// <p>The date and time that the query completed.</p>
    pub fn get_completion_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_date_time
    }
    /// <p>Provides information about an Athena query error.</p>
    pub fn athena_error(mut self, input: crate::types::AthenaError) -> Self {
        self.athena_error = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about an Athena query error.</p>
    pub fn set_athena_error(mut self, input: ::std::option::Option<crate::types::AthenaError>) -> Self {
        self.athena_error = input;
        self
    }
    /// <p>Provides information about an Athena query error.</p>
    pub fn get_athena_error(&self) -> &::std::option::Option<crate::types::AthenaError> {
        &self.athena_error
    }
    /// Consumes the builder and constructs a [`QueryExecutionStatus`](crate::types::QueryExecutionStatus).
    pub fn build(self) -> crate::types::QueryExecutionStatus {
        crate::types::QueryExecutionStatus {
            state: self.state,
            state_change_reason: self.state_change_reason,
            submission_date_time: self.submission_date_time,
            completion_date_time: self.completion_date_time,
            athena_error: self.athena_error,
        }
    }
}
