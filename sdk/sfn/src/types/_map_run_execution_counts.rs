// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about all of the child workflow executions started by a Map Run.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MapRunExecutionCounts {
    /// <p>The total number of child workflow executions that were started by a Map Run, but haven't started executing yet.</p>
    pub pending: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run and are currently in-progress.</p>
    pub running: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run and have completed successfully.</p>
    pub succeeded: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run, but have failed.</p>
    pub failed: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run and have timed out.</p>
    pub timed_out: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run and were running, but were either stopped by the user or by Step Functions because the Map Run failed.</p>
    pub aborted: i64,
    /// <p>The total number of child workflow executions that were started by a Map Run.</p>
    pub total: i64,
    /// <p>Returns the count of child workflow executions whose results were written by <code>ResultWriter</code>. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultwriter.html">ResultWriter</a> in the <i>Step Functions Developer Guide</i>.</p>
    pub results_written: i64,
    /// <p>The number of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> child workflow executions that cannot be redriven because their execution status is terminal. For example, child workflows with an execution status of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> and a <code>redriveStatus</code> of <code>NOT_REDRIVABLE</code>.</p>
    pub failures_not_redrivable: ::std::option::Option<i64>,
    /// <p>The number of unsuccessful child workflow executions currently waiting to be redriven. The status of these child workflow executions could be <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> in the original execution attempt or a previous redrive attempt.</p>
    pub pending_redrive: ::std::option::Option<i64>,
}
impl MapRunExecutionCounts {
    /// <p>The total number of child workflow executions that were started by a Map Run, but haven't started executing yet.</p>
    pub fn pending(&self) -> i64 {
        self.pending
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and are currently in-progress.</p>
    pub fn running(&self) -> i64 {
        self.running
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have completed successfully.</p>
    pub fn succeeded(&self) -> i64 {
        self.succeeded
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but have failed.</p>
    pub fn failed(&self) -> i64 {
        self.failed
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have timed out.</p>
    pub fn timed_out(&self) -> i64 {
        self.timed_out
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and were running, but were either stopped by the user or by Step Functions because the Map Run failed.</p>
    pub fn aborted(&self) -> i64 {
        self.aborted
    }
    /// <p>The total number of child workflow executions that were started by a Map Run.</p>
    pub fn total(&self) -> i64 {
        self.total
    }
    /// <p>Returns the count of child workflow executions whose results were written by <code>ResultWriter</code>. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultwriter.html">ResultWriter</a> in the <i>Step Functions Developer Guide</i>.</p>
    pub fn results_written(&self) -> i64 {
        self.results_written
    }
    /// <p>The number of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> child workflow executions that cannot be redriven because their execution status is terminal. For example, child workflows with an execution status of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> and a <code>redriveStatus</code> of <code>NOT_REDRIVABLE</code>.</p>
    pub fn failures_not_redrivable(&self) -> ::std::option::Option<i64> {
        self.failures_not_redrivable
    }
    /// <p>The number of unsuccessful child workflow executions currently waiting to be redriven. The status of these child workflow executions could be <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> in the original execution attempt or a previous redrive attempt.</p>
    pub fn pending_redrive(&self) -> ::std::option::Option<i64> {
        self.pending_redrive
    }
}
impl MapRunExecutionCounts {
    /// Creates a new builder-style object to manufacture [`MapRunExecutionCounts`](crate::types::MapRunExecutionCounts).
    pub fn builder() -> crate::types::builders::MapRunExecutionCountsBuilder {
        crate::types::builders::MapRunExecutionCountsBuilder::default()
    }
}

/// A builder for [`MapRunExecutionCounts`](crate::types::MapRunExecutionCounts).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MapRunExecutionCountsBuilder {
    pub(crate) pending: ::std::option::Option<i64>,
    pub(crate) running: ::std::option::Option<i64>,
    pub(crate) succeeded: ::std::option::Option<i64>,
    pub(crate) failed: ::std::option::Option<i64>,
    pub(crate) timed_out: ::std::option::Option<i64>,
    pub(crate) aborted: ::std::option::Option<i64>,
    pub(crate) total: ::std::option::Option<i64>,
    pub(crate) results_written: ::std::option::Option<i64>,
    pub(crate) failures_not_redrivable: ::std::option::Option<i64>,
    pub(crate) pending_redrive: ::std::option::Option<i64>,
}
impl MapRunExecutionCountsBuilder {
    /// <p>The total number of child workflow executions that were started by a Map Run, but haven't started executing yet.</p>
    /// This field is required.
    pub fn pending(mut self, input: i64) -> Self {
        self.pending = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but haven't started executing yet.</p>
    pub fn set_pending(mut self, input: ::std::option::Option<i64>) -> Self {
        self.pending = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but haven't started executing yet.</p>
    pub fn get_pending(&self) -> &::std::option::Option<i64> {
        &self.pending
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and are currently in-progress.</p>
    /// This field is required.
    pub fn running(mut self, input: i64) -> Self {
        self.running = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and are currently in-progress.</p>
    pub fn set_running(mut self, input: ::std::option::Option<i64>) -> Self {
        self.running = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and are currently in-progress.</p>
    pub fn get_running(&self) -> &::std::option::Option<i64> {
        &self.running
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have completed successfully.</p>
    /// This field is required.
    pub fn succeeded(mut self, input: i64) -> Self {
        self.succeeded = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have completed successfully.</p>
    pub fn set_succeeded(mut self, input: ::std::option::Option<i64>) -> Self {
        self.succeeded = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have completed successfully.</p>
    pub fn get_succeeded(&self) -> &::std::option::Option<i64> {
        &self.succeeded
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but have failed.</p>
    /// This field is required.
    pub fn failed(mut self, input: i64) -> Self {
        self.failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but have failed.</p>
    pub fn set_failed(mut self, input: ::std::option::Option<i64>) -> Self {
        self.failed = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run, but have failed.</p>
    pub fn get_failed(&self) -> &::std::option::Option<i64> {
        &self.failed
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have timed out.</p>
    /// This field is required.
    pub fn timed_out(mut self, input: i64) -> Self {
        self.timed_out = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have timed out.</p>
    pub fn set_timed_out(mut self, input: ::std::option::Option<i64>) -> Self {
        self.timed_out = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and have timed out.</p>
    pub fn get_timed_out(&self) -> &::std::option::Option<i64> {
        &self.timed_out
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and were running, but were either stopped by the user or by Step Functions because the Map Run failed.</p>
    /// This field is required.
    pub fn aborted(mut self, input: i64) -> Self {
        self.aborted = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and were running, but were either stopped by the user or by Step Functions because the Map Run failed.</p>
    pub fn set_aborted(mut self, input: ::std::option::Option<i64>) -> Self {
        self.aborted = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run and were running, but were either stopped by the user or by Step Functions because the Map Run failed.</p>
    pub fn get_aborted(&self) -> &::std::option::Option<i64> {
        &self.aborted
    }
    /// <p>The total number of child workflow executions that were started by a Map Run.</p>
    /// This field is required.
    pub fn total(mut self, input: i64) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run.</p>
    pub fn set_total(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total = input;
        self
    }
    /// <p>The total number of child workflow executions that were started by a Map Run.</p>
    pub fn get_total(&self) -> &::std::option::Option<i64> {
        &self.total
    }
    /// <p>Returns the count of child workflow executions whose results were written by <code>ResultWriter</code>. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultwriter.html">ResultWriter</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// This field is required.
    pub fn results_written(mut self, input: i64) -> Self {
        self.results_written = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the count of child workflow executions whose results were written by <code>ResultWriter</code>. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultwriter.html">ResultWriter</a> in the <i>Step Functions Developer Guide</i>.</p>
    pub fn set_results_written(mut self, input: ::std::option::Option<i64>) -> Self {
        self.results_written = input;
        self
    }
    /// <p>Returns the count of child workflow executions whose results were written by <code>ResultWriter</code>. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/input-output-resultwriter.html">ResultWriter</a> in the <i>Step Functions Developer Guide</i>.</p>
    pub fn get_results_written(&self) -> &::std::option::Option<i64> {
        &self.results_written
    }
    /// <p>The number of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> child workflow executions that cannot be redriven because their execution status is terminal. For example, child workflows with an execution status of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> and a <code>redriveStatus</code> of <code>NOT_REDRIVABLE</code>.</p>
    pub fn failures_not_redrivable(mut self, input: i64) -> Self {
        self.failures_not_redrivable = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> child workflow executions that cannot be redriven because their execution status is terminal. For example, child workflows with an execution status of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> and a <code>redriveStatus</code> of <code>NOT_REDRIVABLE</code>.</p>
    pub fn set_failures_not_redrivable(mut self, input: ::std::option::Option<i64>) -> Self {
        self.failures_not_redrivable = input;
        self
    }
    /// <p>The number of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> child workflow executions that cannot be redriven because their execution status is terminal. For example, child workflows with an execution status of <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> and a <code>redriveStatus</code> of <code>NOT_REDRIVABLE</code>.</p>
    pub fn get_failures_not_redrivable(&self) -> &::std::option::Option<i64> {
        &self.failures_not_redrivable
    }
    /// <p>The number of unsuccessful child workflow executions currently waiting to be redriven. The status of these child workflow executions could be <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> in the original execution attempt or a previous redrive attempt.</p>
    pub fn pending_redrive(mut self, input: i64) -> Self {
        self.pending_redrive = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of unsuccessful child workflow executions currently waiting to be redriven. The status of these child workflow executions could be <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> in the original execution attempt or a previous redrive attempt.</p>
    pub fn set_pending_redrive(mut self, input: ::std::option::Option<i64>) -> Self {
        self.pending_redrive = input;
        self
    }
    /// <p>The number of unsuccessful child workflow executions currently waiting to be redriven. The status of these child workflow executions could be <code>FAILED</code>, <code>ABORTED</code>, or <code>TIMED_OUT</code> in the original execution attempt or a previous redrive attempt.</p>
    pub fn get_pending_redrive(&self) -> &::std::option::Option<i64> {
        &self.pending_redrive
    }
    /// Consumes the builder and constructs a [`MapRunExecutionCounts`](crate::types::MapRunExecutionCounts).
    pub fn build(self) -> crate::types::MapRunExecutionCounts {
        crate::types::MapRunExecutionCounts {
            pending: self.pending.unwrap_or_default(),
            running: self.running.unwrap_or_default(),
            succeeded: self.succeeded.unwrap_or_default(),
            failed: self.failed.unwrap_or_default(),
            timed_out: self.timed_out.unwrap_or_default(),
            aborted: self.aborted.unwrap_or_default(),
            total: self.total.unwrap_or_default(),
            results_written: self.results_written.unwrap_or_default(),
            failures_not_redrivable: self.failures_not_redrivable,
            pending_redrive: self.pending_redrive,
        }
    }
}
